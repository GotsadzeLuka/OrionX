import assert from "node:assert/strict";
import {spawn, spawnSync, type ChildProcess} from "node:child_process";
import {randomBytes} from "node:crypto";
import {readFile,writeFile,mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {resolve} from "node:path";
import {PrismaClient} from "@prisma/client";
import {claimJob, renewJobLease, LeaseLostError} from "../packages/core/src/jobs";

async function main() {
 const base=process.env.DIRECT_URL || process.env.DATABASE_URL;
 if(process.env.ORIONX_ISOLATED_TEST!=="1" || !base || !["localhost","127.0.0.1"].includes(new URL(base).hostname)) {
   throw Error("Only ORIONX_ISOLATED_TEST=1 on disposable loopback PostgreSQL is permitted");
 }
 const schema="worker_crash_"+randomBytes(5).toString("hex"), url=new URL(base);
 url.searchParams.set("schema",schema);
 const temp=await mkdtemp(resolve(tmpdir(),"orionx-worker-crash-"));
 const admin=new PrismaClient({datasourceUrl:base});
 const a=new PrismaClient({datasourceUrl:url.toString()}), b=new PrismaClient({datasourceUrl:url.toString()});
 let child:ChildProcess|undefined;
 try {
  // Use the complete repository schema, not just the initial architecture.
  // Later migrations define queue constraints and revocation privileges used
  // by the current Prisma Client. Identical setup to the isolated validator.
  const migrations = ["0001_architecture", "0002_proof_context", "0003_student_workspace",
    "0004_assessments", "0005_revocation", "0006_revocation_function_privileges"];
  const statements=await Promise.all(migrations.map(async name =>
    (await readFile(`packages/db/prisma/migrations/${name}/migration.sql`,"utf8"))
      .replace("REVOKE EXECUTE ON FUNCTION public.rls_auto_enable() FROM PUBLIC, anon, authenticated;",
        "-- Supabase-only helper not present in disposable PostgreSQL")
      .replaceAll("public.",'"'+schema+'".')
  ));
  const roleSetup="DO \u0024\u0024 BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon; END IF; IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated; END IF; END \u0024\u0024;";
  const path=resolve(temp,"setup.sql");
  await writeFile(path,roleSetup+'CREATE SCHEMA IF NOT EXISTS "'+schema+'"; SET search_path TO "'+schema+'"; ALTER DEFAULT PRIVILEGES IN SCHEMA "'+schema+'" GRANT EXECUTE ON FUNCTIONS TO anon, authenticated;\n'+statements.join("\n"));
  const setup=spawnSync(process.execPath,["node_modules/prisma/build/index.js","db","execute","--schema","packages/db/prisma/schema.prisma","--file",path],{env:{...process.env,DATABASE_URL:url.toString(),DIRECT_URL:url.toString()},encoding:"utf8"});
  if(setup.status!==0)throw Error("Isolated queue schema failed: "+setup.stderr);
  const job=await a.job.create({data:{type:"SYNC",stage:"SYNC",idempotencyKey:"crash:"+randomBytes(8).toString("hex")}});
  child=spawn(process.execPath,["--import","tsx","scripts/worker-lease-child.ts"],{
    env:{...process.env,DATABASE_URL:url.toString(),DIRECT_URL:url.toString(),TEST_WORKER_OWNER:"crashed-owner",TEST_WORKER_SCHEMA:schema},
    stdio:["ignore","pipe","pipe"],
  });
  const claimed=await new Promise<string>((resolve,reject)=>{
    let stdout="",stderr="";
    const t=setTimeout(()=>reject(Error("Child did not claim a job: "+stderr)),15000);
    child!.stdout!.on("data",data=>{
      stdout+=data.toString();
      const m=stdout.match(/CLAIMED:([^\n]+)/);
      if(m){clearTimeout(t);resolve(m[1].trim());}
    });
    child!.stderr!.on("data",data=>stderr+=data.toString());
    child!.once("exit",code=>{clearTimeout(t);reject(Error("Child exited early: "+code+" "+stderr));});
  });
  assert.equal(claimed,job.id);
  child.kill("SIGKILL");
  await new Promise<void>(resolve=>child!.once("exit",()=>resolve()));
  child=undefined;
  const orphan=await a.job.findUniqueOrThrow({where:{id:job.id}});
  assert.equal(orphan.state,"RENDERED");
  assert.equal(orphan.leaseOwner,"crashed-owner");
  // Simulate elapsed lease time in PostgreSQL instead of sleeping an entire lease.
  await a.job.update({where:{id:job.id},data:{leaseUntil:new Date(Date.now()-60000)}});
  const recovered=await claimJob(b,schema,"recovered-owner",60000);
  assert.equal(recovered,job.id);
  await assert.rejects(renewJobLease(a,schema,job.id,"crashed-owner",60000),LeaseLostError);
  const stale=await a.job.updateMany({where:{id:job.id,leaseOwner:"crashed-owner",state:"RENDERED",leaseUntil:{gt:new Date()}},data:{state:"COMPLETED"}});
  assert.equal(stale.count,0);
  const committed=await b.job.updateMany({where:{id:job.id,leaseOwner:"recovered-owner",state:"RENDERED",leaseUntil:{gt:new Date()}},data:{state:"COMPLETED",leaseOwner:null,leaseUntil:null}});
  assert.equal(committed.count,1);

  const jobs=await a.job.createMany({data:Array.from({length:30},(_,i)=>({type:"SYNC",stage:"SYNC",idempotencyKey:"concurrent:"+i+":"+schema}))});
  assert.equal(jobs.count,30);
  const claimedIds=new Set<string>();
  for(let i=0;i<15;i++){
    const ids=await Promise.all([claimJob(a,schema,"worker-a",60000),claimJob(b,schema,"worker-b",60000)]);
    for(const id of ids){assert.ok(id);assert.equal(claimedIds.has(id!),false);claimedIds.add(id!);}
  }
  assert.equal(claimedIds.size,30);
  assert.equal(await claimJob(a,schema,"worker-a",60000),undefined);
  console.log(JSON.stringify({realTerminatedProcess:true,recoveredAfterExpiredLease:true,staleCommitRejected:true,uniqueConcurrentClaims:30,syntheticOnly:true}));
 } finally {
  if(child){child.kill("SIGKILL");}
  await a.$disconnect();await b.$disconnect();
  await admin.$executeRawUnsafe('DROP SCHEMA IF EXISTS "'+schema+'" CASCADE');
  await admin.$disconnect();await rm(temp,{recursive:true,force:true});
 }
}
main().catch(e=>{console.error(e instanceof Error?e.message:String(e));process.exitCode=1});
