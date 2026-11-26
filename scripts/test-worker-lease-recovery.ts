import assert from "node:assert/strict";
import {spawn, type ChildProcess} from "node:child_process";
import {randomBytes} from "node:crypto";
import {once} from "node:events";
import {mkdtemp, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {resolve} from "node:path";
import {PrismaClient} from "@prisma/client";
import {claimJob, finishClaimedJob, renewJobLease, LeaseLostError} from "../packages/core/src/jobs";
import {createPostgresRateLimiter} from "../apps/api/src/rate-limit";
import {applyIsolatedMigrations, requireIsolatedPostgres} from "./isolated-postgres";

async function claimedByChild(child: ChildProcess): Promise<string> {
  return new Promise((ready, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error("Worker did not report its claim")), 15_000);
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", code => { clearTimeout(timer); reject(new Error("Worker exited before claim: " + code)); });
    child.stdout?.on("data", bytes => {
      output += bytes.toString();
      const id = output.match(/CLAIMED:([^\n]+)/)?.[1].trim();
      if (id) { clearTimeout(timer); ready(id); }
    });
  });
}

async function main() {
  const base = requireIsolatedPostgres();
  const schema = "worker_crash_" + randomBytes(5).toString("hex");
  const url = new URL(base);
  url.searchParams.set("schema", schema);
  const temp = await mkdtemp(resolve(tmpdir(), "orionx-worker-crash-"));
  const admin = new PrismaClient({datasourceUrl: base});
  const a = new PrismaClient({datasourceUrl: url.href});
  const b = new PrismaClient({datasourceUrl: url.href});
  let child: ChildProcess | undefined;
  try {
    await applyIsolatedMigrations(url, temp);
    const job = await a.job.create({data: {type: "SYNC", stage: "SYNC", idempotencyKey: "sync:crash"}});
    child = spawn(process.execPath, ["--import", "tsx", "scripts/worker-lease-child.ts"], {
      env: {...process.env, DATABASE_URL: url.href, DIRECT_URL: url.href, TEST_WORKER_OWNER: "terminated-owner", TEST_WORKER_SCHEMA: schema},
      stdio: ["ignore", "pipe", "inherit"],
    });
    assert.equal(await claimedByChild(child), job.id);
    const childExit = once(child, "exit");
    child.kill("SIGKILL");
    assert.deepEqual(await childExit, [null, "SIGKILL"]);
    child = undefined;

    const orphan = await a.job.findUniqueOrThrow({where: {id: job.id}});
    assert.equal(orphan.state, "RENDERED");
    assert.equal(orphan.leaseOwner, "terminated-owner");
    assert.equal(await claimJob(b, schema, "recovered-owner", 60_000), undefined);
    await a.job.update({where: {id: job.id}, data: {leaseUntil: new Date(0)}});
    assert.equal(await claimJob(b, schema, "recovered-owner", 60_000), job.id);
    await assert.rejects(renewJobLease(a, schema, job.id, "terminated-owner", 60_000), LeaseLostError);
    await assert.rejects(a.$transaction(tx => finishClaimedJob(tx, job.id, "terminated-owner", {state: "COMPLETED"})), LeaseLostError);
    await b.$transaction(tx => finishClaimedJob(tx, job.id, "recovered-owner", {state: "COMPLETED"}));
    assert.equal((await a.job.findUniqueOrThrow({where: {id: job.id}})).state, "COMPLETED");

    await a.job.createMany({
      data: Array.from({length: 30}, (_, index) => ({type: "SYNC", stage: "SYNC", idempotencyKey: "concurrent:" + index})),
    });
    const claimed = new Set<string>();
    for (let index = 0; index < 15; index++) {
      const ids = await Promise.all([claimJob(a, schema, "worker-a", 60_000), claimJob(b, schema, "worker-b", 60_000)]);
      for (const id of ids) {
        assert.ok(id);
        assert.equal(claimed.has(id), false);
        claimed.add(id);
      }
    }
    assert.equal(claimed.size, 30);
    assert.equal(await claimJob(a, schema, "worker-a", 60_000), undefined);

    const sharedA = createPostgresRateLimiter(a);
    const sharedB = createPostgresRateLimiter(b);
    // Retry on a minute rollover so the assertion compares one database window.
    let decisions: Awaited<ReturnType<typeof sharedA>>[] = [];
    for (let attempt = 0; attempt < 2; attempt++) {
      const start = Math.floor(Date.now() / 60_000);
      decisions = await Promise.all(Array.from({length: 8}, (_, index) =>
        (index % 2 === 0 ? sharedA : sharedB)("synthetic:upload:" + attempt, 5),
      ));
      if (Math.floor(Date.now() / 60_000) === start) break;
    }
    assert.equal(decisions.filter(decision => decision.allowed).length, 5);
    assert.equal((await a.apiRateLimitBucket.findMany()).every(bucket => /^[a-f0-9]{64}$/.test(bucket.bucketKey)), true);
    console.log(JSON.stringify({
      terminatedProcess: true, unfinishedJobRecovered: true, staleCommitRejected: true,
      uniqueConcurrentClaims: claimed.size, allowedAcrossTwoRateLimiterInstances: 5,
    }));
  } finally {
    child?.kill("SIGKILL");
    await a.$disconnect();
    await b.$disconnect();
    await admin.$executeRawUnsafe('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE');
    await admin.$disconnect();
    await rm(temp, {recursive: true, force: true});
  }
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
