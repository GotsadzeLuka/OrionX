# Reproduce worker, validator and throughput checks

Use Node.js 22 and a disposable PostgreSQL 16 database on loopback. Match the credentials to your local test database.

```sh
npm ci
npm run db:generate
export ORIONX_ISOLATED_TEST=1
export DATABASE_URL='postgresql://orionx:local@127.0.0.1:5432/orionx'
export DIRECT_URL="$DATABASE_URL"
npm run test:worker:crash
npm run test:capacity
```

The scripts apply all migrations in a uniquely named schema and remove that schema afterward. The crash test terminates a separate Node process after it claims a job, expires the database lease, and calls the production fencing code to check that the original owner cannot finish the job. Two PostgreSQL clients then claim 30 jobs and share one request-rate window.

The benchmark loads 5,000 synthetic students, passports, awards, versions, and jobs. It times bulk persistence, 50 claims at concurrency two, and ten PDF renders. It reports claim percentiles, CPU and memory from the Node process, and runtime and database versions. The sample includes no blockchain writes. These numbers describe this workload and its local environment.

## Isolated chain lifecycle

The [workflow](../.github/workflows/revocation-integration.yml) pins and checksum-verifies the Agave compiler and validator tools. Install those tools and Rust, then run:

```sh
cargo test --locked
npm run test:revocation:integration
```

The lifecycle compiles a temporary program with an ephemeral administrator and uses a loopback validator and synthetic fixture rows. It verifies finalized versions, scoped revocation authority, failed-RPC handling, recovery after recorded on-chain finality, and a corrected issuance while retaining historical evidence.

## Rate limits in deployment

`ORIONX_RATE_LIMIT_STORE=memory` maintains a bounded per-process request window. For a shared window across instances, apply migration `0007_api_rate_limits` and configure `ORIONX_RATE_LIMIT_STORE=postgres`. The adapter stores hashed bucket identifiers, coordinates counters in PostgreSQL, prunes old windows, and returns a retryable HTTP 503 when the database cannot enforce the limit. Keep authentication and public edge quotas aligned with your deployment's throughput.
