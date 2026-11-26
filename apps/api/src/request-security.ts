import {randomUUID} from "node:crypto";
import type {Request, Response, NextFunction} from "express";
import {authenticate, requireAdmin} from "@orionx/core";
import {prisma} from "@orionx/db";
import {createMemoryRateLimiter, createPostgresRateLimiter} from "./rate-limit";

export const cookie = (req: Request, key: string) =>
  (req.headers.cookie || "")
    .split(";")
    .map(c => c.trim())
    .find(c => c.startsWith(key + "="))
    ?.slice(key.length + 1);

export function bearerFromRequest(req: Request): string | undefined {
  return req.headers.authorization || (cookie(req, "orionx_access") ? "Bearer " + cookie(req, "orionx_access") : undefined);
}

export async function identity(req: Request) {
  return authenticate(bearerFromRequest(req));
}

export async function admin(req: Request) {
  const id = await identity(req);
  requireAdmin(id);
  return id;
}

export function requestProtoAndHost(req: Request): {protocol: string; host: string; directHost: string} {
  const protocol = req.protocol === "https" || process.env.VERCEL === "1" ? "https" : "http";
  const forwardedHost = process.env.VERCEL === "1" ? String(req.headers["x-forwarded-host"] || "").split(",")[0].trim() : "";
  const directHost = String(req.headers.host || "").split(",")[0].trim();
  return {protocol, host: forwardedHost || directHost, directHost};
}

function isOriginAllowed(req: Request, origin: string): boolean {
  if (process.env.WEB_ORIGIN) {
    return origin === process.env.WEB_ORIGIN;
  }
  const {protocol, host, directHost} = requestProtoAndHost(req);
  const trusted = new Set<string>(
    [
      host ? `${protocol}://${host}` : undefined,
      directHost ? `${protocol}://${directHost}` : undefined,
      directHost ? `${req.protocol}://${directHost}` : undefined,
      process.env.VERIFICATION_PUBLIC_ORIGIN,
      process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : undefined,
      process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : undefined,
    ].filter(Boolean) as string[],
  );
  if (trusted.has(origin)) return true;
  if (process.env.NODE_ENV !== "production" && process.env.VERCEL !== "1") {
    try {
      const parsed = new URL(origin);
      if (parsed.protocol === "http:" && ["localhost", "127.0.0.1"].includes(parsed.hostname)) return true;
    } catch {
      return false;
    }
  }
  return false;
}

export function createRequestSecurity() {
  const store = process.env.ORIONX_RATE_LIMIT_STORE || "memory";
  if (store !== "memory" && store !== "postgres") {
    throw new Error("ORIONX_RATE_LIMIT_STORE must be memory or postgres");
  }
  const checkLimit = store === "postgres" ? createPostgresRateLimiter(prisma) : createMemoryRateLimiter();
  return async (req: Request, res: Response, next: NextFunction) => {
    const path = req.path.toLowerCase().replace(/\/+$/, "");
    const correlationId = randomUUID();
    res.setHeader("X-Correlation-Id", correlationId);
    res.setHeader("X-Content-Type-Options", "nosniff");
    if (path.startsWith("/api/v1/")) res.setHeader("Cache-Control", "no-store");

    const {origin, authorization} = req.headers;
    if (req.method === "POST" &&
        ((origin && !isOriginAllowed(req, origin)) || (!origin && req.headers.cookie && !authorization))) {
      res.status(403).json({error: {code: "INVALID_ORIGIN", message: "Request origin rejected"}, correlationId});
      return;
    }
    if (req.method === "OPTIONS" || path === "/api/v1/health/live") {
      next();
      return;
    }
    const category = path === "/api/v1/verify/file" ? "upload" : path.startsWith("/api/v1/auth/") ? "auth" : "request";
    const limit = category === "upload" ? 5 : category === "auth" ? 20 : 60;
    const key = `${req.ip || req.socket.remoteAddress || "unknown"}:${category}`;
    try {
      const decision = await checkLimit(key, limit);
      if (!decision.allowed) {
        res.setHeader("Retry-After", String(decision.retryAfter));
        res.status(429).json({error: {code: "RATE_LIMITED", message: "Try again later", retryable: true}, correlationId});
        return;
      }
    } catch {
      // An unavailable shared store must not silently remove the guard.
      res.status(503).json({error: {code: "RATE_LIMIT_UNAVAILABLE", message: "Service unavailable; try again later", retryable: true}, correlationId});
      return;
    }
    next();
  };
}
