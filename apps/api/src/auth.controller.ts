import {Body, Controller, Get, HttpCode, Post, Query, Req, Res} from "@nestjs/common";
import type {Request, Response} from "express";
import {
  buildGoogleAuthorizeUrl, createPkceChallenge, openOAuthState, resolveAllowedWebOrigin,
  resolveSession, sanitizeRedirectPath, sealOAuthState,
} from "@orionx/core";
import {supabaseAuthServiceConfig} from "@orionx/core/src/config";
import {DomainError} from "@orionx/core/src/errors";
import {z} from "zod";
import {bearerFromRequest, cookie, requestProtoAndHost} from "./request-security";

@Controller("api/v1")
export class AuthController {
  private cookieFlags(req?: Request) {
    return process.env.NODE_ENV === "production" || req?.protocol === "https" ? "; Secure" : "";
  }

  private clearOAuthCookie(req?: Request) {
    return "orionx_oauth=; HttpOnly; SameSite=Lax; Path=/api/v1/auth; Max-Age=0" + this.cookieFlags(req);
  }

  private sessionCookies(res: Response, session: {access_token: string; refresh_token: string; expires_in?: number}, req?: Request) {
    const secure = this.cookieFlags(req);
    const maxAge = Math.min(Number(session.expires_in) || 3600, 3600);
    res.setHeader("Set-Cookie", [
      `orionx_access=${session.access_token}; HttpOnly; SameSite=Strict; Path=/api/v1; Max-Age=${maxAge}${secure}`,
      `orionx_refresh=${session.refresh_token}; HttpOnly; SameSite=Strict; Path=/api/v1/auth; Max-Age=604800${secure}`,
      this.clearOAuthCookie(req),
    ]);
  }

  private startGoogleOAuth(req: Request, res: Response, rawNext?: unknown) {
    const next = sanitizeRedirectPath(rawNext, "/passport");
    const {protocol, host} = requestProtoAndHost(req);
    const webOrigin = resolveAllowedWebOrigin({
      origin: req.headers.origin,
      protocol,
      host,
    });
    const config = supabaseAuthServiceConfig();
    const {codeVerifier, codeChallenge, state} = createPkceChallenge();
    const sealed = sealOAuthState({state, verifier: codeVerifier, next}, config.cookieSecret);
    const secure = this.cookieFlags(req);
    res.setHeader("Set-Cookie", [`orionx_oauth=${sealed}; HttpOnly; SameSite=Lax; Path=/api/v1/auth; Max-Age=600${secure}`]);
    res.setHeader("Cache-Control", "no-store");
    const url = buildGoogleAuthorizeUrl({
      supabaseOrigin: config.url,
      redirectUri: `${webOrigin}/auth/callback`,
      codeChallenge,
    });
    return {url, state, next};
  }

  @Get("auth/google")
  async googleRedirect(@Query("next") next: string | undefined, @Req() req: Request, @Res() res: Response) {
    const {url} = this.startGoogleOAuth(req, res, next);
    res.redirect(302, url);
  }

  @Post("auth/google")
  @HttpCode(200)
  async googleInit(@Body() body: unknown, @Req() req: Request, @Res() res: Response) {
    const parsed = z.object({next: z.string().max(512).optional()}).safeParse(body ?? {});
    if (!parsed.success) throw new DomainError("INVALID_REQUEST", "Invalid Google sign-in request", 400);
    const result = this.startGoogleOAuth(req, res, parsed.data.next);
    res.json({provider: "google", ...result});
  }

  private async completeGoogleCallback(
    req: Request,
    res: Response,
    params: {code?: unknown; state?: unknown; error?: unknown; errorDescription?: unknown},
  ) {
    if (typeof params.error === "string" && params.error.trim()) {
      res.setHeader("Set-Cookie", [this.clearOAuthCookie(req)]);
      const detail =
        typeof params.errorDescription === "string" && params.errorDescription.trim()
          ? params.errorDescription.trim().slice(0, 200)
          : "Google authentication was cancelled or denied";
      throw new DomainError("OAUTH_PROVIDER_ERROR", detail, 401);
    }
    const parsed = z
      .object({
        code: z.string().min(1).max(512),
        state: z.string().max(512).optional(),
      })
      .safeParse({code: params.code, state: params.state || undefined});
    if (!parsed.success) {
      res.setHeader("Set-Cookie", [this.clearOAuthCookie(req)]);
      throw new DomainError("INVALID_REQUEST", "Authorization code is required", 400);
    }
    const config = supabaseAuthServiceConfig();
    let oauthState: {state: string; verifier: string; next: string};
    try {
      oauthState = openOAuthState(cookie(req, "orionx_oauth"), parsed.data.state, config.cookieSecret);
    } catch (error) {
      res.setHeader("Set-Cookie", [this.clearOAuthCookie(req)]);
      throw error;
    }

    const response = await fetch(`${config.url}/auth/v1/token?grant_type=pkce`, {
      method: "POST",
      headers: {apikey: config.apikey, "Content-Type": "application/json"},
      body: JSON.stringify({auth_code: parsed.data.code, code_verifier: oauthState.verifier}),
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) {
      res.setHeader("Set-Cookie", [this.clearOAuthCookie(req)]);
      throw new DomainError("UNAUTHENTICATED", "Unable to complete Google sign-in; authorization code expired or invalid", 401);
    }
    const session = await response.json();
    if (!session?.access_token || !session?.refresh_token) {
      res.setHeader("Set-Cookie", [this.clearOAuthCookie(req)]);
      throw new DomainError("UNAUTHENTICATED", "Incomplete session received from authentication provider", 401);
    }
    const resolved = await resolveSession("Bearer " + session.access_token);
    this.sessionCookies(res, session, req);
    res.setHeader("Cache-Control", "no-store");
    const redirectTo =
      resolved.role === "admin" && (oauthState.next === "/passport" || oauthState.next === "/login" || oauthState.next === "/")
        ? "/admin"
        : oauthState.next;
    return {
      authenticated: true,
      authorized: resolved.authorized,
      role: resolved.role,
      verification: resolved.verification,
      workspaceId: resolved.workspaceId,
      studentId: resolved.studentId,
      subject: resolved.subject,
      email: resolved.email,
      redirectTo,
    };
  }

  @Get("auth/callback")
  async callbackGet(@Query() query: Record<string, unknown>, @Req() req: Request, @Res() res: Response) {
    const {protocol, host} = requestProtoAndHost(req);
    const webOrigin = resolveAllowedWebOrigin({
      origin: req.headers.origin,
      protocol,
      host,
    });
    try {
      const result = await this.completeGoogleCallback(req, res, {
        code: query.code,
        state: query.state,
        error: query.error,
        errorDescription: query.error_description || query.errorDescription,
      });
      res.redirect(302, `${webOrigin}${result.redirectTo}`);
    } catch (error) {
      const message = error instanceof DomainError ? error.message : "Unable to complete Google sign-in";
      res.redirect(302, `${webOrigin}/login?error=${encodeURIComponent(message)}`);
    }
  }

  @Post("auth/callback")
  @HttpCode(200)
  async callbackPost(@Body() body: unknown, @Req() req: Request, @Res() res: Response) {
    const record = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
    const result = await this.completeGoogleCallback(req, res, {
      code: record.code,
      state: record.state,
      error: record.error,
      errorDescription: record.error_description || record.errorDescription,
    });
    res.json(result);
  }

  @Post("auth/login")
  @HttpCode(200)
  async login(@Body() body: unknown) {
    const parsed = z.object({email: z.string().email().max(254), password: z.string().min(1).max(256)}).safeParse(body);
    if (!parsed.success) throw new DomainError("INVALID_REQUEST", "Email/password sign-in is disabled; use Google OAuth", 400);
    throw new DomainError("AUTH_METHOD_DISABLED", "Password sign-in is disabled. Continue with Google.", 403);
  }

  @Post("auth/refresh")
  @HttpCode(200)
  async refresh(@Req() req: Request, @Res() res: Response) {
    const refresh = cookie(req, "orionx_refresh");
    if (!refresh) throw new DomainError("UNAUTHENTICATED", "Sign in required", 401);
    const config = supabaseAuthServiceConfig();
    const response = await fetch(`${config.url}/auth/v1/token?grant_type=refresh_token`, {
      method: "POST",
      headers: {apikey: config.apikey, "Content-Type": "application/json"},
      body: JSON.stringify({refresh_token: refresh}),
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) {
      const secure = this.cookieFlags(req);
      res.setHeader("Set-Cookie", [
        `orionx_access=; HttpOnly; SameSite=Strict; Path=/api/v1; Max-Age=0${secure}`,
        `orionx_refresh=; HttpOnly; SameSite=Strict; Path=/api/v1/auth; Max-Age=0${secure}`,
        this.clearOAuthCookie(req),
      ]);
      throw new DomainError("UNAUTHENTICATED", "Session expired", 401);
    }
    const session = await response.json();
    const resolved = await resolveSession("Bearer " + session.access_token);
    this.sessionCookies(res, session, req);
    res.setHeader("Cache-Control", "no-store");
    res.json({ok: true, authenticated: true, authorized: resolved.authorized, role: resolved.role, verification: resolved.verification});
  }

  @Post("auth/logout")
  @HttpCode(200)
  async logout(@Req() req: Request, @Res() res: Response) {
    const accessToken = cookie(req, "orionx_access");
    if (accessToken) {
      try {
        const config = supabaseAuthServiceConfig();
        await fetch(`${config.url}/auth/v1/logout`, {
          method: "POST",
          headers: {apikey: config.apikey, Authorization: `Bearer ${accessToken}`},
          signal: AbortSignal.timeout(5000),
        });
      } catch {
        // Always clear local cookies even if remote logout fails.
      }
    }
    const secure = this.cookieFlags(req);
    res.setHeader("Set-Cookie", [
      `orionx_access=; HttpOnly; SameSite=Strict; Path=/api/v1; Max-Age=0${secure}`,
      `orionx_refresh=; HttpOnly; SameSite=Strict; Path=/api/v1/auth; Max-Age=0${secure}`,
      this.clearOAuthCookie(req),
    ]);
    res.setHeader("Cache-Control", "no-store");
    res.json({ok: true});
  }

  @Get("auth/session")
  async session(@Req() req: Request, @Res() res: Response) {
    const user = await resolveSession(bearerFromRequest(req));
    res.setHeader("Cache-Control", "no-store");
    res.json({
      authenticated: true,
      authorized: user.authorized,
      role: user.role,
      verification: user.verification,
      workspaceId: user.workspaceId,
      studentId: user.studentId,
      subject: user.subject,
      email: user.email,
    });
  }
}
