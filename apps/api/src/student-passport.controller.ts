import {Controller, Get, Param, Query, Req, Res} from "@nestjs/common";
import type {Request, Response} from "express";
import {prisma} from "@orionx/db";
import {artifactStore, sha256, verifyDevnet, type Snapshot} from "@orionx/core";
import {DomainError} from "@orionx/core/src/errors";
import {identity} from "./request-security";

const summary = (
  v: {number: number; state: string; code: string; pageCount: number | null; createdAt: Date; finalizedAt: Date | null; snapshot: unknown; chainCluster?: string | null; revocation?: {state: string; finalizedAt: Date | null} | null},
  latest: number,
) => ({
  version: v.number,
  state: v.state,
  verificationCode: v.code,
  pageCount: v.pageCount,
  createdAt: v.createdAt,
  finalizedAt: v.finalizedAt,
  isLatest: v.number === latest && !v.revocation,
  credentialStatus: v.revocation?.state || (v.number === latest ? "UNKNOWN" : "SUPERSEDED"),
  revocation: v.revocation ? {state: v.revocation.state, finalizedAt: v.revocation.finalizedAt, message: "This version is not available as a valid credential. Contact the university for assistance."} : null,
  originalIssueDate: (v.snapshot as Snapshot).student.initialIssueDate,
  skillAwardCount: (v.snapshot as Snapshot).awards.length,
  issuerTrust: "DEMO",
  cluster: v.chainCluster || "devnet",
});

@Controller("api/v1/me/passport")
export class StudentPassportController {
  /** Resolve the authenticated student's own passport record. */
  private async ownPassport(req: Request) {
   const user = await identity(req);
   if (user.role === "admin" && !user.studentId) throw new DomainError("NOT_FOUND", "Administrators have no student passport", 404);
   const passport = user.studentId ? await prisma.passport.findUnique({where: {studentId: user.studentId}, include: {student: true}}) : null;
   return {user, passport};
  }
  @Get() async myPassport(@Req() req: Request, @Res() res: Response) {
   const {user, passport} = await this.ownPassport(req);
   res.setHeader("Cache-Control", "no-store");

   // A reserved database passport/ID is NOT an issued credential. Only a
   // stored, blockchain-finalized PDF version may unlock the student view.
   const latest = passport && passport.latestFinalizedVersion > 0
     ? await prisma.version.findUnique({where: {passportId_number: {passportId: passport.id, number: passport.latestFinalizedVersion}}, include: {revocation: true}})
     : null;
   const issued = !!passport && !!latest?.finalizedSlot && !!latest.storageKey && !!latest.pdfSha256;
   if (!issued || !passport || !latest) {
    const pending = !!passport?.activeVersionId;
    res.json({
      official: false,
      status: pending ? "ISSUANCE_PENDING" : passport ? "NOT_ISSUED" : "EMPTY_WORKSPACE",
      // Never disclose a reserved Passport ID, its issue date or its underlying chain data.
      passportId: null,
      workspaceId: user.workspaceId ?? null,
      verification: user.verification,
      universityVerified: user.verification === "UNIVERSITY_VERIFIED",
      account: {email: user.email ?? null},
      originalIssueDate: null,
      student: null,
      latest: null,
      pending,
      counts: {skills: 0, badges: 0, versions: 0},
    });
    return;
   }

   const liveProof = await verifyDevnet(latest.code);
   const latestSummary = {...summary(latest, passport.latestFinalizedVersion), issuerTrust: liveProof.issuerTrust ?? "UNCONFIRMED"};
   const activeProof = liveProof.registration === "REGISTERED" && liveProof.revocation === "VALID";
   const studentLatest = liveProof.revocation === "REVOKED"
     ? {...latestSummary, isLatest: false, credentialStatus: "REVOKED", revocation: {
       state: "REVOKED",
       finalizedAt: liveProof.revocationEvidence ? new Date(Number(liveProof.revocationEvidence.revokedUnix) * 1000) : null,
       message: "This version was revoked. Contact the university for assistance.",
     }}
     : {
       ...latestSummary,
       isLatest: activeProof && liveProof.currency !== "SUPERSEDED" && !latest.revocation,
       credentialStatus: latest.revocation?.state ?? (activeProof
         ? liveProof.currency === "SUPERSEDED" ? "SUPERSEDED" : "VALID"
         : "UNKNOWN"),
     };
   const finalized = await prisma.version.count({where: {passportId: passport.id, finalizedSlot: {not: null}}});
   const awardCount = (latest.snapshot as unknown as Snapshot).awards.length;
   res.json({
     // A finalized Devnet demo credential does not prove BTU endorsement.
     // "official" requires independently verified issuer trust, not mere issuance.
     official: activeProof && liveProof.officialBtu === true && !latest.revocation,
     issuerTrust: liveProof.issuerTrust,
     blockchainRegistration: liveProof.registration,
     onChainRevocation: liveProof.revocation ?? "UNKNOWN",
     documentIntegrity: liveProof.integrity,
     status: studentLatest.revocation ? studentLatest.revocation.state === "REVOKED" ? "REVOKED" : "REVOCATION_PENDING" : studentLatest.credentialStatus === "UNKNOWN" ? "VERIFICATION_UNAVAILABLE" : "ISSUED",
     workspaceId: null,
     verification: user.verification,
     // Identity verification and institutional credential attestation differ.
     universityVerified: user.verification === "UNIVERSITY_VERIFIED",
     account: {email: user.email ?? null},
     counts: {skills: awardCount, badges: awardCount, versions: finalized},
     passportId: passport.publicId,
     originalIssueDate: passport.initialIssueDate.toISOString().slice(0, 10),
     student: {firstName: passport.student.firstName, lastName: passport.student.lastName, program: passport.student.program, educationLevel: passport.student.educationLevel},
     latest: studentLatest,
     pending: !!passport.activeVersionId,
   });
  }
  @Get("versions") async myVersions(@Req() req: Request, @Res() res: Response) {
   const {passport} = await this.ownPassport(req);
   res.setHeader("Cache-Control", "no-store");
   if (!passport) { res.json([]); return; }
   const versions = await prisma.version.findMany({where: {passportId: passport.id, finalizedSlot: {not: null}}, take: 100, orderBy: {number: "desc"}, include: {revocation: true}});
   res.json(versions.map(v => ({...summary(v, passport.latestFinalizedVersion), awards: (v.snapshot as unknown as Snapshot).awards})));
  }
 @Get("versions/:version/download") async download(
  @Req() req: Request, @Res() res: Response,
  @Param("version") number: string,
  @Query("inline") inline: string | undefined,
 ) {
  const {passport} = await this.ownPassport(req);
  if (!passport || passport.latestFinalizedVersion < 1) throw new DomainError("NOT_FOUND", "Issued version not found", 404);
  if (!/^[1-9]\d{0,8}$/.test(number)) throw new DomainError("INVALID_REQUEST", "Invalid version", 400);
  const version = await prisma.version.findUnique({where: {passportId_number: {passportId: passport.id, number: Number(number)}}, include: {revocation: true}});
  if (!version?.finalizedSlot || !version.storageKey || !version.pdfSha256 || version.number > passport.latestFinalizedVersion) {
    throw new DomainError("NOT_FOUND", "Issued version not found", 404);
  }
  if (version.revocation) throw new DomainError("CREDENTIAL_REVOKED", "This version is revoked or awaiting revocation; contact the university", 409);
  const bytes = await artifactStore().get(version.storageKey);
  if (sha256(bytes) !== version.pdfSha256) throw new DomainError("ARTIFACT_CORRUPTED", "Stored document failed integrity validation", 503);
  const proof = await verifyDevnet(version.code, bytes);
  if (proof.revocation !== "VALID" || proof.registration !== "REGISTERED" || proof.integrity !== "MATCH") {
    throw new DomainError(proof.errorCode || "PROOF_UNAVAILABLE", proof.message, proof.revocation === "REVOKED" ? 409 : 503);
  }
  res.setHeader("Cache-Control", "private, no-store");
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Disposition", (inline === "1" ? "inline" : "attachment") + '; filename="passport-v' + version.number + '.pdf"');
  res.send(Buffer.from(bytes));
 }
}
