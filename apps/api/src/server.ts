import "reflect-metadata";
import {NestFactory} from "@nestjs/core";
import {Module, Controller, Get, Post, Param, Query, Req, Res, Body, HttpCode, Catch, type ArgumentsHost, type ExceptionFilter, HttpException} from "@nestjs/common";
import type {Request, Response} from "express";
import {randomUUID} from "node:crypto";
import {prisma} from "@orionx/db";
import type {Prisma} from "@prisma/client";
import {
  decodeCode,
  verifyDevnet,
  sha256,
  artifactStore,
  bindIdentity,
  linkWorkspaceToStudent,
  extractVerificationCodesFromPdf,
  type Snapshot,
} from "@orionx/core";
import {DomainError} from "@orionx/core/src/errors";
import {queueSynchronization, listCatalogSkills, appendSourceAward} from "@orionx/core/src/sync";
import {createJobProcessor} from "@orionx/core/src/processor";
import {z} from "zod";
import multer from "multer";
import {requestRevocation, requestCorrection} from "@orionx/core/src/revocation";
import {publicPassport} from "./public-passport";
import {AuthController} from "./auth.controller";
import {StudentPassportController} from "./student-passport.controller";
import {admin, createRequestSecurity} from "./request-security";

const safeJSON = (value: unknown) => JSON.parse(JSON.stringify(value, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

@Catch()
class Errors implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost) {
    const res = host.switchToHttp().getResponse<Response>();
    const known = error instanceof DomainError;
    const http = error instanceof HttpException;
    const status = known ? error.status : http ? error.getStatus() : 503;
    const code = status === 404 ? "NOT_FOUND" : status < 500 ? "INVALID_REQUEST" : "SERVICE_UNAVAILABLE";
    const message = status === 404 ? "Route not found" : status < 500 ? "Invalid request" : "Service unavailable; try again later";
    res.status(status).json({
      error: {
        code: known ? error.code : code,
        message: known ? error.message : message,
        retryable: known ? error.retryable : status >= 500,
      },
      correlationId: res.getHeader("X-Correlation-Id"),
    });
  }
}

@Controller("api/v1")
class ApiController {
  @Get("health/live")
  live() {
    return {status: "ok", service: "orionx-api"};
  }

  @Get("health/ready")
  async ready() {
    try {
      await prisma.$queryRaw`SELECT 1`;
      return {status: "ok", issuance: process.env.CHAIN_MODE === "devnet" ? "configured" : "offline", source: process.env.SOURCE_MODE || "fixture"};
    } catch {
      throw new DomainError("NOT_READY", "Database unavailable", 503, true);
    }
  }

  @Get("admin/overview")
  async adminOverview(@Req() req: Request) {
    await admin(req);
    const [
      passportsTotal,
      studentsTotal,
      versionsFinalized,
      awardsTotal,
      activeUpdates,
      jobsGrouped,
      workspacesTotal,
      workspacesUnlinked,
      bindingsStudent,
      bindingsAdmin,
      bindingsDual,
      latestSyncRun,
    ] = await Promise.all([
      prisma.passport.count(),
      prisma.student.count(),
      prisma.version.count({where: {finalizedSlot: {not: null}}}),
      prisma.award.count(),
      prisma.passport.count({where: {activeVersionId: {not: null}}}),
      prisma.job.groupBy({by: ["state"], _count: {_all: true}}),
      prisma.studentWorkspace.count(),
      prisma.studentWorkspace.count({where: {linkedStudentId: null}}),
      prisma.studentIdentity.count({where: {role: "student"}}),
      prisma.studentIdentity.count({where: {role: "admin"}}),
      prisma.studentIdentity.count({where: {role: "admin", studentId: {not: null}}}),
      prisma.importRun.findFirst({orderBy: {createdAt: "desc"}, include: {_count: {select: {conflicts: true}}}}),
    ]);
    const jobsByState = Object.fromEntries(jobsGrouped.map(g => [g.state, g._count._all]));
    return {
      passportsTotal,
      studentsTotal,
      versionsFinalized,
      awardsTotal,
      activeUpdates,
      sourceSpreadsheetUrl: process.env.SOURCE_MODE === "sheets" && process.env.GOOGLE_SHEET_ID
        ? `https://docs.google.com/spreadsheets/d/${encodeURIComponent(process.env.GOOGLE_SHEET_ID)}/edit`
        : null,
      jobs: {
        queued: (jobsByState.QUEUED || 0) + (jobsByState.DISCOVERED || 0) + (jobsByState.VALIDATED || 0),
        running: (jobsByState.RENDERED || 0) + (jobsByState.STORED || 0) + (jobsByState.CHAIN_PENDING || 0) + (jobsByState.SYNC_WRITEBACK_PENDING || 0),
        retryWait: jobsByState.RETRY_WAIT || 0,
        blocked: (jobsByState.BLOCKED_CONFLICT || 0) + (jobsByState.FAILED_PERMANENT || 0),
        completed: (jobsByState.COMPLETED || 0) + (jobsByState.FINALIZED || 0),
      },
      accounts: {
        workspacesTotal,
        workspacesUnlinked,
        bindingsStudent,
        bindingsAdmin,
        bindingsDual,
      },
      latestSyncRun,
    };
  }

  @Post("admin/identities")
  @HttpCode(200)
  async bindAdminIdentity(@Req() req: Request, @Body() body: unknown) {
    const actor = await admin(req);
    const parsed = z
      .object({
        subject: z.string().min(1).max(128),
        role: z.enum(["student", "admin"]),
        studentExternalId: z.string().min(1).max(64).optional(),
        studentId: z.string().min(1).max(64).optional(),
        preserveStudentLink: z.boolean().optional(),
        provider: z.string().min(1).max(256).optional(),
      })
      .safeParse(body);
    if (!parsed.success) throw new DomainError("INVALID_REQUEST", "Valid subject, role, and student reference required", 400);
    const binding = await bindIdentity({
      subject: parsed.data.subject,
      role: parsed.data.role,
      studentExternalId: parsed.data.studentExternalId,
      studentId: parsed.data.studentId,
      preserveStudentLink: parsed.data.preserveStudentLink,
      provider: parsed.data.provider,
      verifiedBy: actor.subject,
    });
    return {ok: true, binding};
  }

  @Post("admin/identities/unlink")
  @HttpCode(200)
  async unlinkAdminIdentity(@Req() req: Request, @Body() body: unknown) {
    const actor = await admin(req);
    const parsed = z
      .object({
        subject: z.string().min(1).max(128),
        provider: z.string().min(1).max(256).optional(),
      })
      .safeParse(body);
    if (!parsed.success) throw new DomainError("INVALID_REQUEST", "Valid subject is required", 400);
    const subject = parsed.data.subject.trim();
    if (subject === actor.subject) {
      throw new DomainError("INVALID_REQUEST", "You cannot remove your own active administrator binding", 400);
    }
    await prisma.$transaction(async tx => {
      const deleted = await tx.studentIdentity.deleteMany({
        where: {subject, ...(parsed.data.provider ? {provider: parsed.data.provider} : {})},
      });
      await tx.studentWorkspace.updateMany({
        where: {subject, ...(parsed.data.provider ? {provider: parsed.data.provider} : {})},
        data: {linkedStudentId: null, linkedBy: null, linkedAt: null},
      });
      await tx.auditEvent.create({
        data: {
          actorId: actor.subject,
          action: "IDENTITY_UNBOUND",
          targetId: subject,
          detail: {deletedCount: deleted.count},
        },
      });
    });
    return {ok: true};
  }

  @Get("admin/accounts")
  async adminAccounts(@Req() req: Request, @Query() query: Record<string, string | undefined>) {
    await admin(req);
    const q = (query.q || "").trim();
    const skip = Math.max(0, Number(query.skip) || 0);
    const take = Math.min(500, Math.max(1, Number(query.take) || 200));

    const [identities, workspaces, students] = await Promise.all([
      prisma.studentIdentity.findMany({
        where: q
          ? {
              OR: [
                {subject: {contains: q, mode: "insensitive"}},
                {role: {contains: q, mode: "insensitive"}},
                {student: {OR: [{externalId: {contains: q, mode: "insensitive"}}, {firstName: {contains: q, mode: "insensitive"}}, {lastName: {contains: q, mode: "insensitive"}}, {email: {contains: q, mode: "insensitive"}}]}},
              ],
            }
          : undefined,
        include: {
          student: {
            select: {
              id: true,
              externalId: true,
              firstName: true,
              lastName: true,
              email: true,
              program: true,
              passport: {select: {publicId: true, latestFinalizedVersion: true}},
            },
          },
        },
        orderBy: {verifiedAt: "desc"},
        skip,
        take,
      }),
      prisma.studentWorkspace.findMany({
        where: q
          ? {
              OR: [
                {workspaceId: {contains: q, mode: "insensitive"}},
                {email: {contains: q, mode: "insensitive"}},
                {subject: {contains: q, mode: "insensitive"}},
              ],
            }
          : undefined,
        orderBy: {createdAt: "desc"},
        skip,
        take,
      }),
      prisma.student.findMany({
        where: q
          ? {
              OR: [
                {externalId: {contains: q, mode: "insensitive"}},
                {firstName: {contains: q, mode: "insensitive"}},
                {lastName: {contains: q, mode: "insensitive"}},
                {email: {contains: q, mode: "insensitive"}},
                {program: {contains: q, mode: "insensitive"}},
              ],
            }
          : undefined,
        include: {
          passport: {select: {id: true, publicId: true, latestFinalizedVersion: true}},
          identities: {select: {id: true, subject: true, role: true, provider: true, verifiedAt: true}},
        },
        orderBy: {externalId: "asc"},
        skip,
        take,
      }),
    ]);

    const allWorkspacesBySubject = new Map(workspaces.map(w => [w.subject, w]));
    const allStudentsById = new Map(students.map(s => [s.id, s]));
    const allIdentitiesBySubject = new Map(identities.map(i => [i.subject, i]));

    return {
      identities: identities.map(i => ({
        ...i,
        workspace: allWorkspacesBySubject.get(i.subject) || null,
      })),
      workspaces: workspaces.map(w => ({
        ...w,
        linkedStudent: w.linkedStudentId ? allStudentsById.get(w.linkedStudentId) || null : null,
        binding: allIdentitiesBySubject.get(w.subject) || null,
      })),
      students,
    };
  }

  @Get("admin/workspaces")
  async workspaces(@Req() req: Request, @Query() query: Record<string, string | undefined>) {
    await admin(req);
    const q = (query.q || "").trim();
    const skip = Math.max(0, Number(query.skip) || 0);
    const take = Math.min(500, Math.max(1, Number(query.take) || 100));
    return prisma.studentWorkspace.findMany({
      where: q
        ? {
            OR: [
              {workspaceId: {contains: q, mode: "insensitive"}},
              {email: {contains: q, mode: "insensitive"}},
              {subject: {contains: q, mode: "insensitive"}},
            ],
          }
        : undefined,
      skip,
      take,
      orderBy: {createdAt: "desc"},
      select: {workspaceId: true, email: true, subject: true, linkedStudentId: true, linkedAt: true, createdAt: true},
    });
  }

  @Post("admin/workspaces/:workspaceId/link")
  @HttpCode(200)
  async linkWorkspace(@Req() req: Request, @Param("workspaceId") workspaceId: string, @Body() body: unknown) {
    const actor = await admin(req);
    const parsed = z
      .object({studentExternalId: z.string().min(1).max(64).optional(), studentId: z.string().min(1).max(64).optional()})
      .refine(v => Boolean(v.studentExternalId) !== Boolean(v.studentId), "Provide exactly one student reference")
      .safeParse(body);
    if (!parsed.success || !/^WS-[A-Z2-7]{16}$/.test(workspaceId)) {
      throw new DomainError("INVALID_REQUEST", "Valid workspace and exactly one student reference required", 400);
    }
    const result = await linkWorkspaceToStudent({workspaceId, ...parsed.data, linkedBy: actor.subject});
    return {ok: true, workspaceId, studentId: result.studentId, alreadyLinked: result.alreadyLinked};
  }

  @Post("admin/sync")
  @HttpCode(202)
  async sync(@Req() req: Request) {
    const user = await admin(req);
    return queueSynchronization(String(req.headers["idempotency-key"] || randomUUID()), user.subject);
  }
  @Post("admin/jobs/process")
  @HttpCode(200)
  async processJobs(@Req() req: Request) {
    await admin(req);
    if (process.env.MANUAL_WORKER_ENABLED !== "true") throw new DomainError("PROCESSOR_DISABLED", "On-demand processing is not enabled", 503);
    if (process.env.STORAGE_MODE !== "supabase" || process.env.CHAIN_MODE !== "devnet" || process.env.SOURCE_MODE !== "sheets") throw new DomainError("PROCESSOR_UNCONFIGURED", "Live source, private storage and Devnet must be configured", 503);
    if (!process.env.SOLANA_ISSUER_KEYPAIR_JSON && !process.env.SOLANA_ISSUER_KEYPAIR_PATH) throw new DomainError("PROCESSOR_UNCONFIGURED", "Server-side issuer credential is missing", 503);
    const result = await createJobProcessor({writebackLimit: 1}).processNext();
    const active = {type: {in: ["ISSUE", "SYNC"]}, state: {in: ["QUEUED", "RETRY_WAIT", "RENDERED"]}} satisfies Prisma.JobWhereInput;
    const [remaining, blocked, next] = await Promise.all([
      prisma.job.count({where: active}),
      prisma.job.count({where: {type: {in: ["ISSUE", "SYNC"]}, state: {in: ["BLOCKED_CONFLICT", "FAILED_PERMANENT"]}}}),
      prisma.job.findFirst({where: active, orderBy: {availableAt: "asc"}, select: {availableAt: true}}),
    ]);
    return {...result, remaining, blocked, nextAvailableAt: next?.availableAt ?? null};
  }

  @Get("admin/jobs")
  async listJobs(@Req() req: Request, @Query() query: Record<string, string | undefined>) {
    await admin(req);
    const filter = (query.state || "ALL").toUpperCase();
    const skip = Math.max(0, Number(query.skip) || 0);
    const take = Math.min(500, Math.max(1, Number(query.take) || 100));
    const where: Prisma.JobWhereInput =
      filter === "ACTIVE"
        ? {state: {in: ["DISCOVERED", "VALIDATED", "QUEUED", "RENDERED", "STORED", "CHAIN_PENDING", "SYNC_WRITEBACK_PENDING", "RETRY_WAIT"]}}
        : filter === "FAILED"
          ? {state: {in: ["BLOCKED_CONFLICT", "FAILED_PERMANENT", "RETRY_WAIT"]}}
          : filter === "COMPLETED"
            ? {state: {in: ["COMPLETED", "FINALIZED"]}}
            : {};

    const [items, total, recentRuns, conflicts] = await Promise.all([
      prisma.job.findMany({
        where,
        include: {
          version: {
            select: {
              id: true,
              number: true,
              code: true,
              state: true,
              txSignature: true,
              passport: {
                select: {
                  id: true,
                  publicId: true,
                  student: {select: {externalId: true, firstName: true, lastName: true}},
                },
              },
            },
          },
        },
        orderBy: [{updatedAt: "desc"}, {createdAt: "desc"}],
        skip,
        take,
      }),
      prisma.job.count({where}),
      prisma.importRun.findMany({
        take: 15,
        orderBy: {createdAt: "desc"},
        include: {conflicts: {take: 50}},
      }),
      prisma.importConflict.findMany({
        take: 100,
        orderBy: {createdAt: "desc"},
      }),
    ]);

    return safeJSON({items, total, skip, take, recentRuns, conflicts});
  }

  @Get("admin/sync-runs/:id")
  async syncRun(@Req() req: Request, @Param("id") id: string) {
    await admin(req);
    const run = await prisma.importRun.findUnique({where: {id}, include: {conflicts: {take: 250}}});
    if (!run) throw new DomainError("NOT_FOUND", "Run not found", 404);
    return run;
  }

  @Get("admin/passports")
  async passports(@Req() req: Request, @Res({passthrough: true}) res: Response, @Query() query: Record<string, string | undefined>) {
    await admin(req);
    const q = (query.q || "").trim();
    const status = (query.status || "").toUpperCase();
    const skip = Math.max(0, Number(query.skip) || 0);
    const take = Math.min(1000, Math.max(1, Number(query.take) || 200));

    const where: Prisma.PassportWhereInput = {
      ...(q
        ? {
            OR: [
              {publicId: {contains: q, mode: "insensitive"}},
              {student: {externalId: {contains: q, mode: "insensitive"}}},
              {student: {firstName: {contains: q, mode: "insensitive"}}},
              {student: {lastName: {contains: q, mode: "insensitive"}}},
              {student: {email: {contains: q, mode: "insensitive"}}},
              {student: {program: {contains: q, mode: "insensitive"}}},
            ],
          }
        : {}),
      ...(status === "ISSUED"
        ? {latestFinalizedVersion: {gt: 0}}
        : status === "PROCESSING"
          ? {activeVersionId: {not: null}}
          : status === "UNISSUED"
            ? {latestFinalizedVersion: 0}
            : {}),
    };

    const isEnvelope = query.envelope === "1" || query.envelope === "true";
    const items = await prisma.passport.findMany({
      where,
      skip,
      take,
      include: {
        student: {
          select: {
            id: true,
            externalId: true,
            firstName: true,
            lastName: true,
            email: true,
            program: true,
            educationLevel: true,
            status: true,
            identities: {select: {id: true, role: true, subject: true, verifiedAt: true}},
          },
        },
        _count: {select: {versions: true}},
      },
      orderBy: {publicId: "asc"},
    });

    if (isEnvelope) {
      const total = await prisma.passport.count({where});
      res.setHeader("X-Total-Count", String(total));
      return {items, total, skip, take};
    }
    return items;
  }

  @Get("admin/passports/:id")
  async passportDetail(@Req() req: Request, @Param("id") id: string) {
    await admin(req);
    const passport = await prisma.passport.findFirst({
      where: {OR: [{publicId: id}, {id}]},
      include: {
        student: {
          include: {
            awards: {orderBy: [{earnedAt: "asc"}, {sourceRecordId: "asc"}]},
            identities: true,
          },
        },
        versions: {
          orderBy: {number: "desc"},
          include: {
            jobs: {orderBy: {createdAt: "desc"}},
            writebacks: true,
            revocation: true,
          },
        },
      },
    });
    if (!passport) throw new DomainError("NOT_FOUND", "Passport not found", 404);
    const subjects = passport.student.identities.map(i => i.subject);
    const [workspaces, sourceSyncs] = await Promise.all([
      prisma.studentWorkspace.findMany({
        where: {
          OR: [
            {linkedStudentId: passport.student.id},
            ...(subjects.length ? [{subject: {in: subjects}}] : []),
          ],
        },
      }),
      prisma.sourceSync.findMany({
        where: {sourceStudentId: passport.student.externalId},
        orderBy: {sourceRecordId: "asc"},
      }),
    ]);
    return safeJSON({
      ...passport,
      workspaces,
      sourceSyncs,
    });
  }

  @Post("admin/passports/:id/versions/:version/revoke")
  async revokeVersion(@Req() req: Request, @Param("id") id: string, @Param("version") number: string, @Body() input: unknown) {
    const user = await admin(req);
    const parsed = z.object({reason: z.string().trim().min(1).max(1000), confirm: z.literal(true), withdrawRecordIds: z.array(z.string().min(1)).max(100).default([])}).safeParse(input);
    if (!parsed.success || !/^[1-9]\d{0,8}$/.test(number)) throw new DomainError("INVALID_REQUEST", "Explicit confirmation, version and reason are required", 400);
    return safeJSON(await requestRevocation(user, id, Number(number), parsed.data.reason, parsed.data.withdrawRecordIds));
  }
  @Post("admin/passports/:id/correct")
  async correctPassport(@Req() req: Request, @Param("id") id: string, @Body() input: unknown) {
    const user = await admin(req);
    if (!z.object({confirm: z.literal(true)}).safeParse(input).success) throw new DomainError("INVALID_REQUEST", "Explicit confirmation required", 400);
    const version = await requestCorrection(user, id);
    return {version: version.number, state: version.state};
  }
  @Get("admin/passports/:id/versions")
  async versions(@Req() req: Request, @Param("id") id: string) {
    await admin(req);
    return safeJSON(
      await prisma.version.findMany({
        where: {passport: {OR: [{publicId: id}, {id}]}},
        take: 200,
        orderBy: {number: "desc"},
        include: {jobs: true, writebacks: true, revocation: true},
      }),
    );
  }

  @Get("admin/passports/:id/versions/:version/download")
  async adminDownloadVersion(
    @Req() req: Request,
    @Res() res: Response,
    @Param("id") id: string,
    @Param("version") versionNumber: string,
  ) {
    await admin(req);
    if (!/^[1-9]\d{0,8}$/.test(versionNumber)) throw new DomainError("INVALID_REQUEST", "Invalid version number", 400);
    const passport = await prisma.passport.findFirst({where: {OR: [{publicId: id}, {id}]}});
    if (!passport) throw new DomainError("NOT_FOUND", "Passport not found", 404);
    const version = await prisma.version.findUnique({
      where: {passportId_number: {passportId: passport.id, number: Number(versionNumber)}},
    });
    if (!version?.finalizedSlot || !version.storageKey) {
      throw new DomainError("NOT_FOUND", "Finalized PDF artifact not available for this version", 404);
    }
    const bytes = await artifactStore().get(version.storageKey);
    if (sha256(bytes) !== version.pdfSha256) {
      throw new DomainError("ARTIFACT_CORRUPTED", "Stored document failed integrity validation", 503);
    }
    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${passport.publicId}-v${version.number}.pdf"`);
    res.send(Buffer.from(bytes));
  }

  @Get("admin/catalog")
  async adminCatalog(@Req() req: Request) {
    await admin(req);
    const students = await prisma.student.findMany({
      orderBy: {externalId: "asc"},
      include: {
        passport: {select: {publicId: true, initialIssueDate: true, latestFinalizedVersion: true}},
        awards: {select: {skillId: true, sourceRecordId: true}},
      },
    });
    return {
      skills: listCatalogSkills(),
      students,
      sourceMode: process.env.SOURCE_MODE || "fixture",
    };
  }

  @Post("admin/source/awards")
  @HttpCode(200)
  async addSourceAward(@Req() req: Request, @Body() body: unknown) {
    const actor = await admin(req);
    const parsed = z
      .object({
        studentId: z.string().min(1).max(64),
        firstName: z.string().max(128).optional(),
        lastName: z.string().max(128).optional(),
        email: z.string().max(254).optional(),
        program: z.string().max(200).optional(),
        educationLevel: z.string().max(120).optional(),
        passportId: z.string().max(64).optional(),
        initialIssueDate: z.string().max(32).optional(),
        status: z.enum(["Active", "Graduate"]).optional(),
        skillId: z.string().min(1).max(64),
        recordId: z.string().max(128).optional(),
        dateEarned: z.string().min(10).max(10),
        autoSync: z.boolean().optional(),
      })
      .safeParse(body);
    if (!parsed.success) {
      throw new DomainError("INVALID_REQUEST", "Valid studentId, skillId, and YYYY-MM-DD dateEarned are required", 400);
    }
    const result = await appendSourceAward({
      ...parsed.data,
      actorId: actor.subject,
    });
    let syncRun = "run" in result ? result.run : undefined;
    if (parsed.data.autoSync && result.mode === "sheets") {
      syncRun = await queueSynchronization(randomUUID(), actor.subject);
    }
    return {...result, syncRun};
  }

  @Get("admin/audit")
  async audit(@Req() req: Request, @Query() query: Record<string, string | undefined>) {
    await admin(req);
    const q = (query.q || "").trim();
    const skip = Math.max(0, Number(query.skip) || 0);
    const take = Math.min(500, Math.max(1, Number(query.take) || 100));
    const where: Prisma.AuditEventWhereInput = q
      ? {
          OR: [
            {action: {contains: q, mode: "insensitive"}},
            {actorId: {contains: q, mode: "insensitive"}},
            {targetId: {contains: q, mode: "insensitive"}},
          ],
        }
      : {};
    const isEnvelope = query.envelope === "1" || query.envelope === "true";
    const items = await prisma.auditEvent.findMany({where, skip, take, orderBy: {createdAt: "desc"}});
    if (isEnvelope) {
      const total = await prisma.auditEvent.count({where});
      return {items, total, skip, take};
    }
    return items;
  }
 @Post("admin/jobs/:id/retry") async retry(@Req() req: Request, @Param("id") id: string) {
  const user = await admin(req);
  await prisma.$transaction(async tx => {
   const changed = await tx.job.updateMany({where: {id, state: {in: ["FAILED_PERMANENT", "RETRY_WAIT", "STORED"]}}, data: {state: "QUEUED", attempts: 0, availableAt: new Date(), leaseOwner: null, leaseUntil: null, lastError: null}});
   if (changed.count !== 1) throw new DomainError("NOT_RETRYABLE", "Job requires conflict resolution or is already active", 409);
   const job = await tx.job.findUniqueOrThrow({where: {id}});
   if (job.type === "REVOKE" && job.versionId) await tx.revocation.updateMany({where: {versionId: job.versionId, state: "FAILED"}, data: {state: "PENDING", lastError: null}});
   await tx.auditEvent.create({data: {actorId: user.subject, action: "JOB_RETRIED", targetId: id, detail: {stage: job.stage}}});
  }); return {ok: true};
 }
 @Get("verify/:code/original") async original(@Param("code") code: string, @Res() res: Response) {
  const {result} = await publicPassport(code);
  res.setHeader("Cache-Control", "no-store");
  const status = result.revocation === "REVOKED" ? 409 : result.integrity === "MISMATCH" ? 422 : result.registration === "REGISTERED" ? 200 : result.errorCode === "UNKNOWN_CODE" ? 404 : 503;
  res.status(status).json(result);
 }
 @Get("verify/:code/document") async publicDocument(@Param("code") code: string, @Query("download") download: string | undefined, @Res() res: Response) {
  const {bytes, result} = await publicPassport(code);
  res.setHeader("Cache-Control", "no-store");
  if (!bytes) {
   const status = result.revocation === "REVOKED" ? 409 : result.integrity === "MISMATCH" ? 422 : result.errorCode === "UNKNOWN_CODE" || result.original.errorCode === "ORIGINAL_NOT_FOUND" ? 404 : 503;
   res.status(status).json(result); return;
  }
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Disposition", `${download === "1" ? "attachment" : "inline"}; filename="passport-v${result.version}.pdf"`);
  res.send(Buffer.from(bytes));
 }
 @Get("verify/:code") async verify(@Param("code") code: string, @Res() res: Response) {
  try { decodeCode(code); } catch { throw new DomainError("INVALID_CODE", "Malformed verification code", 400); }
  const proof = await verifyDevnet(code);
  res.setHeader("Cache-Control", "no-store"); res.status(proof.registration === "REGISTERED" ? 200 : proof.errorCode === "UNKNOWN_CODE" ? 404 : 503).json(proof);
 }
 @Post("verify/file") async verifyFile(@Req() req: Request, @Res() res: Response) {
  const upload = multer({storage: multer.memoryStorage(), limits: {fileSize: 10 * 1024 * 1024, files: 1, fields: 1, fieldSize: 128, parts: 2}}).single("file");
  await new Promise<void>((resolve, reject) => upload(req, res, error => error ? reject(new DomainError("UPLOAD_LIMIT", "Upload exceeds multipart limits", 413)) : resolve()));
  const file = req.file;
  if (!file) throw new DomainError("INVALID_PDF", "A PDF file is required", 415);
  try {
    if (file.mimetype !== "application/pdf" || file.buffer.subarray(0, 5).toString() !== "%PDF-") {
      throw new DomainError("INVALID_PDF", "A PDF file is required", 415);
    }
    const discovery = extractVerificationCodesFromPdf(file.buffer);
    let code = String(req.body?.code || "").trim().toUpperCase();
    if (!code && discovery.codes.length === 1) code = discovery.codes[0];
    if (!code && discovery.codes.length > 1) {
      throw new DomainError("AMBIGUOUS_PDF_CODES", `Multiple verification codes found in PDF (${discovery.codes.join(", ")}); select which code to verify.`, 400);
    }
    try { decodeCode(code); } catch {
      throw new DomainError("INVALID_CODE", discovery.unrelatedQrPayloads.length
        ? "PDF contains a QR code outside the OrionX verification format; enter a valid D1- code."
        : "Malformed or missing verification code", 400);
    }
    const proof = await verifyDevnet(code, file.buffer);
    res.setHeader("Cache-Control", "no-store");
    res.status(proof.registration !== "REGISTERED" ? proof.errorCode === "UNKNOWN_CODE" ? 404 : 503 : proof.integrity === "MISMATCH" ? 422 : 200).json({
      ...proof,
      verifiedCode: code,
      discoveredCodes: discovery.codes,
    });
  } finally {
    file.buffer.fill(0);
  }
 }
}
@Module({controllers: [AuthController, StudentPassportController, ApiController]}) class AppModule {}
export async function createApp() {
 const app = await NestFactory.create(AppModule, {bodyParser: true});
 // Vercel terminates TLS and supplies the immediate proxy's forwarded headers.
 if (process.env.VERCEL === "1") app.getHttpAdapter().getInstance().set("trust proxy", 1);
 app.useGlobalFilters(new Errors());
 app.use(createRequestSecurity());
 if (process.env.WEB_ORIGIN) app.enableCors({origin: process.env.WEB_ORIGIN, credentials: true, methods: ["GET", "POST"]});
 return app;
}

let handlerPromise: Promise<(req: Request, res: Response) => void> | undefined;

export default async function handler(req: Request, res: Response) {
 if (!handlerPromise) {
  handlerPromise = createApp().then(async app => {
   await app.init();
   return app.getHttpAdapter().getInstance();
  });
 }
 const instance = await handlerPromise;
 return instance(req, res);
}

if (process.env.ORIONX_SKIP_LISTEN !== "1" && !process.env.AWS_LAMBDA_FUNCTION_NAME && !process.env.VERCEL_REGION) {
 createApp().then(app => app.listen(Number(process.env.PORT || 4000), "0.0.0.0")).catch(() => { console.error("Unable to start API"); process.exitCode = 1; });
}
