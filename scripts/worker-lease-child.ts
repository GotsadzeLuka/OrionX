import {PrismaClient} from "@prisma/client";
import {claimJob} from "../packages/core/src/jobs";

const owner=process.env.TEST_WORKER_OWNER, schema=process.env.TEST_WORKER_SCHEMA;
const url=process.env.DATABASE_URL;
if(process.env.ORIONX_ISOLATED_TEST!=="1" || !url || !owner || !schema || !["localhost","127.0.0.1"].includes(new URL(url).hostname)) throw Error("Isolated loopback database required");
const db=new PrismaClient({datasourceUrl:url});
try {
 const id=await claimJob(db,schema,owner,60000);
 if(!id) throw Error("No queued job to claim");
 process.stdout.write("CLAIMED:"+id+"\n");
 // Deliberately keep the process alive until the test terminates it.
 await new Promise<void>(()=>{});
} finally {await db.$disconnect();}
