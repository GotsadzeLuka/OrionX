import assert from 'node:assert/strict';
import {PrismaClient} from '@prisma/client';
import {randomBytes} from 'node:crypto';
import {mkdtemp, rm} from 'node:fs/promises';
import {availableParallelism, cpus, tmpdir} from 'node:os';
import {join} from 'node:path';
import {fixtureRows} from '../packages/core/src/fixtures';
import {snapshot,newCode,sha256} from '../packages/core/src';
import {renderPassportPdf} from '../packages/core/src/templates';
import {claimJob} from '../packages/core/src/jobs';
import {applyIsolatedMigrations, requireIsolatedPostgres} from './isolated-postgres';
async function main(){
 const name = 'orionx_load_' + randomBytes(5).toString('hex');
 const base = requireIsolatedPostgres();
 const url = new URL(base);
 url.searchParams.set('schema', name);
 const admin = new PrismaClient({datasourceUrl: base});
 const a = new PrismaClient({datasourceUrl: url.href}), b = new PrismaClient({datasourceUrl: url.href});
 const temp = await mkdtemp(join(tmpdir(), 'orionx-capacity-'));
 try {
  await applyIsolatedMigrations(url, temp);
  const [version] = await a.$queryRaw<Array<{version: string}>>`SHOW server_version`;
  const usageStart = process.cpuUsage();
  const seed=fixtureRows()[0],count=5000,rows=Array.from({length:count},(_,i)=>{const student={...seed.student,studentId:'LOAD-'+i,email:'load-'+i+'@example.org',passportId:'DEMO-LOAD-'+i};const award={...seed.award,studentId:student.studentId,recordId:'LOAD-REC-'+i};return {student,award,snapshot:snapshot(student,[award],1,newCode())}});
  const started=performance.now();
  await a.student.createMany({data:rows.map((r,i)=>({id:'student-'+i,externalId:r.student.studentId,email:r.student.email,firstName:r.student.firstName,lastName:r.student.lastName,program:r.student.program,educationLevel:r.student.educationLevel,status:r.student.status}))});
  await a.passport.createMany({data:rows.map((r,i)=>({id:'passport-'+i,studentId:'student-'+i,publicId:r.student.passportId,initialIssueDate:new Date(r.student.initialIssueDate),opaqueChainRef:randomBytes(32).toString('hex')}))});
  await a.award.createMany({data:rows.map((r,i)=>({id:'award-'+i,studentId:'student-'+i,sourceRecordId:r.award.recordId,skillId:r.award.skillId,name:r.award.name,category:r.award.category,badgeCode:r.award.badgeCode,description:r.award.description,earnedAt:new Date(r.award.dateEarned),sourceFingerprint:sha256(Buffer.from(JSON.stringify(r.award)))}))});
  await a.version.createMany({data:rows.map((r,i)=>({id:'version-'+i,passportId:'passport-'+i,number:1,code:r.snapshot.code,codeHash:sha256(Buffer.from(r.snapshot.code)),intentDigest:sha256(Buffer.from(JSON.stringify(r.snapshot.awards))),snapshot:JSON.parse(JSON.stringify(r.snapshot)),stagingKey:'load/'+i+'/'+r.snapshot.code+'/artifact.pdf',state:'QUEUED'}))});
  await a.versionAward.createMany({data:rows.map((_,i)=>({versionId:'version-'+i,awardId:'award-'+i,displayOrder:0}))});
  await a.job.createMany({data:rows.map((_,i)=>({versionId:'version-'+i,type:'ISSUE',stage:'PDF',idempotencyKey:'load:'+i}))});
  const persistSeconds=(performance.now()-started)/1000;assert.equal(await a.student.count(),count);assert.equal(await a.job.count(),count);
  const claimed = new Set<string>();
  const claimLatencyMs: number[] = [];
  const claimStart = performance.now();
  const timedClaim = async (db: PrismaClient, worker: string) => {
   const start = performance.now();
   const id = await claimJob(db, name, worker, 120_000);
   claimLatencyMs.push(performance.now() - start);
   return id;
  };
  for (let round = 0; round < 25; round++) {
   for (const id of await Promise.all([timedClaim(a, 'worker-a'), timedClaim(b, 'worker-b')])) {
    assert.ok(id);
    assert.equal(claimed.has(id), false);
    claimed.add(id);
   }
  }
  assert.equal(claimed.size, 50);
  const claimSeconds = (performance.now() - claimStart) / 1000;
  claimLatencyMs.sort((left, right) => left - right);
  const percentile = (p: number) => claimLatencyMs[Math.ceil(claimLatencyMs.length * p) - 1];
  const renderStart = performance.now();
  let totalBytes = 0;
  for (const row of rows.slice(0,10)) totalBytes += (await renderPassportPdf(row.snapshot)).length;
  const cpu = process.cpuUsage(usageStart);
  console.log(JSON.stringify({
   environment: {
    node: process.version, postgres: version.server_version,
    cpu: cpus()[0]?.model, availableParallelism: availableParallelism(), os: process.platform + '/' + process.arch,
   },
   syntheticPassports: count, syntheticAwards: count, syntheticVersions: count, durableJobs: count,
   persistSeconds, claimSeconds, concurrentClaimers: 2, claimedJobs: claimed.size, failedClaims: 0,
   claimLatencyMs: {p50: percentile(0.50), p95: percentile(0.95), p99: percentile(0.99)},
   samplePdfs: 10, samplePdfBytes: totalBytes, renderSeconds: (performance.now() - renderStart) / 1000,
   nodeCpuMs: (cpu.user + cpu.system) / 1000, nodeMaxRssKiB: process.resourceUsage().maxRSS,
   devnetTransactions: 0,
  }));

 }finally{await a.$disconnect();await b.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA IF EXISTS "'+name+'" CASCADE');await admin.$disconnect();await rm(temp,{recursive:true,force:true})}
}
main().catch(e=>{console.error(e.message);process.exitCode=1});
