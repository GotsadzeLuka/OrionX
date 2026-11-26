import {createHash} from "node:crypto";
import type {PrismaClient} from "@prisma/client";

const WINDOW_SECONDS = 60;
const WINDOW_MS = WINDOW_SECONDS * 1000;
type RateLimitDecision = {allowed: boolean; retryAfter: number};
export type RateLimiter = (key: string, limit: number) => Promise<RateLimitDecision>;

export function createMemoryRateLimiter(clock = Date.now, maxBuckets = 10_000): RateLimiter {
  const buckets = new Map<string, number>();
  let window = -1;

  return async (key, limit) => {
    const now = clock();
    const current = Math.floor(now / WINDOW_MS);
    if (current !== window) {
      buckets.clear();
      window = current;
    }
    const retryAfter = Math.ceil(((window + 1) * WINDOW_MS - now) / 1000);
    const hits = buckets.get(key) ?? 0;
    if (hits >= limit || (hits === 0 && buckets.size >= maxBuckets)) {
      return {allowed: false, retryAfter};
    }
    buckets.set(key, hits + 1);
    return {allowed: true, retryAfter};
  };
}

export function createPostgresRateLimiter(db: Pick<PrismaClient, "$queryRaw" | "$executeRaw">): RateLimiter {
  let nextPrune = 0;
  return async (key, limit) => {
    if (Date.now() >= nextPrune) {
      nextPrune = Date.now() + WINDOW_MS;
      await db.$executeRaw`
        DELETE FROM orionx_api_rate_limit_buckets WHERE bucket_key IN (
          SELECT bucket_key FROM orionx_api_rate_limit_buckets
          WHERE window_id < floor(extract(epoch FROM statement_timestamp()) / ${WINDOW_SECONDS})::bigint - 2
          ORDER BY window_id LIMIT 1000 FOR UPDATE SKIP LOCKED
        )
      `;
    }
    // Store a digest instead of a literal source address. Buckets are
    // ephemeral operational state with a fixed window on the database clock.
    const bucket = createHash("sha256").update(key).digest("hex");
    const [result] = await db.$queryRaw<Array<{allowed: boolean; retryAfter: number}>>`
      WITH tick AS (
        SELECT floor(extract(epoch FROM statement_timestamp()) / ${WINDOW_SECONDS})::bigint AS window_id
      ), updated AS (
        INSERT INTO orionx_api_rate_limit_buckets (bucket_key, window_id, hits)
        SELECT ${bucket}, window_id, 1 FROM tick
        ON CONFLICT (bucket_key) DO UPDATE SET
          window_id = GREATEST(orionx_api_rate_limit_buckets.window_id, EXCLUDED.window_id),
          hits = CASE
            WHEN orionx_api_rate_limit_buckets.window_id >= EXCLUDED.window_id
              THEN LEAST(orionx_api_rate_limit_buckets.hits + 1, ${limit + 1}::integer)
            ELSE 1
          END
        RETURNING hits, window_id
      )
      SELECT hits <= ${limit}::integer AS allowed,
        GREATEST(1, ceil((window_id + 1) * ${WINDOW_SECONDS} - extract(epoch FROM statement_timestamp())))::integer AS "retryAfter"
      FROM updated
    `;
    if (!result) throw new Error("Rate limit store did not return a decision");
    return result;
  };
}
