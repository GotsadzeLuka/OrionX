# Isolated worker crash recovery

Run `ORIONX_ISOLATED_TEST=1 DATABASE_URL=postgresql://... DIRECT_URL=... npm run test:worker:crash` **only against a disposable loopback PostgreSQL instance**.

This test:
1. Initializes an isolated schema using the existing base migration.
2. Launches a separate Node child process that claims a real PostgreSQL job.
3. Sends `SIGKILL`, observing the job remains durably leased.
4. Simulates lease expiration by moving the PostgreSQL lease timestamp into the past.
5. Reclaims the job with another worker, rejects stale-worker renewals/commits, and completes it once.
6. Tests concurrent `FOR UPDATE SKIP LOCKED` claims with two clients and 30 distinct jobs.

This specifically proves the queue's crash/lease/fencing behavior in PostgreSQL; it does **not** prove uninterrupted PDF rendering, RPC broadcast, Google Sheets writeback, or hosted unattended processing. It does not start a validator or mutate Devnet. The isolated revocation workflow runs it before the blockchain-dependent tests.

Verification status: implementation committed, no successful CI run observed yet.
