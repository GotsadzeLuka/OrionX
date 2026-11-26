# Institutional trust semantics

A credential finalized on Solana Devnet is **not automatically an officially endorsed university credential**.

- `universityVerified`: the current user's **account/identity** has been university-verified; it is not proof that a particular PDF was institutionally issued.
- `issuerTrust`: verified independent institutional issuer attestation (`BTU_CONFIRMED`) or `DEMO`, `UNCONFIRMED`, `UNAUTHORIZED`.
- `blockchainRegistration`: whether the chain registration was observed; an unavailable RPC returns `UNKNOWN`.
- `onChainRevocation`: `VALID`, `REVOKED`, or `UNKNOWN`.
- `documentIntegrity`: comparison of submitted/stored document bytes with chain hash, or `NOT_CHECKED`.
- `official`: retains the legacy boolean. It requires registered, currently valid proof, verified institutional trust, and no local pending revocation.
- `status: ISSUED` describes a finalized stored version and is not synonymous with institutional endorsement.

A saved PDF, blockchain account, verified account identity, and third-party university attestation establish different claims.

## Verification limitations

The committed read-only Devnet fixture still has `revoked: null`. The successful read-only workflow is **not** strict live-revocation proof. Do not change that fixture or mutate Devnet without independent authorization. This PR also needs the existing API integration suite and TypeScript checks executed successfully before merge.

The revised `official` field intentionally changes its previous overbroad semantics. Consumers that used it to detect *any* finalized demo passport should use `status` instead; display university endorsement only with independently validated issuer trust.
