CREATE TABLE "orionx_api_rate_limit_buckets" (
  "bucket_key" TEXT PRIMARY KEY,
  "window_id" BIGINT NOT NULL,
  "hits" INTEGER NOT NULL CHECK ("hits" BETWEEN 1 AND 61)
);

CREATE INDEX "orionx_api_rate_limit_buckets_window_id_idx"
  ON "orionx_api_rate_limit_buckets" ("window_id");

ALTER TABLE "orionx_api_rate_limit_buckets" ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE "orionx_api_rate_limit_buckets" FROM PUBLIC, anon, authenticated;
