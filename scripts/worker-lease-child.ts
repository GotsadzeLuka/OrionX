import {PrismaClient} from "@prisma/client";
import {claimJob} from "../packages/core/src/jobs";

import {requireIsolatedPostgres} from "./isolated-postgres";

async function main() {
  const owner = process.env.TEST_WORKER_OWNER;
  const schema = process.env.TEST_WORKER_SCHEMA;
  const url = requireIsolatedPostgres();
  if (!owner || !schema) throw new Error("Worker test requires a lease owner and schema");
  const db = new PrismaClient({datasourceUrl: url});
  try {
    const id = await claimJob(db, schema, owner, 60_000);
    if (!id) throw new Error("No queued job to claim");
    process.stdout.write("CLAIMED:" + id + "\n");
    // The parent verifies that the job stays leased after this process dies.
    await new Promise<void>(() => { setInterval(() => {}, 1000); });
  } finally {
    await db.$disconnect();
  }
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
