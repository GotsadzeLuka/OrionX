import {readFile} from "node:fs/promises";
import {createPublicKey, verify} from "node:crypto";

export type TrustStatus = "BTU_CONFIRMED" | "DEMO" | "UNCONFIRMED" | "UNAUTHORIZED";

type IssuerContext = {programId: string; genesisHash: string; configPda: string; issuer: string; epoch: number; admin: string; registeredUnix: bigint};

function encodedBytes(value: unknown, length: number): Buffer | null {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== length || bytes.toString("base64") !== value) return null;
  return bytes;
}

function epochTime(value: unknown): bigint | null {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^\\d{1,20}$/.test(value)) return BigInt(value);
  return null;
}

/** Confirm only a signed, independently pinned institutional trust manifest.
 * Wrong/missing/malformed evidence never grants issuer authorization.
 */
export async function issuerTrust(input: IssuerContext): Promise<TrustStatus> {
  if (process.env.ISSUER_TRUST_MODE === "DEMO") return "DEMO";
  const path = process.env.BTU_TRUST_MANIFEST_PATH;
  const root = process.env.BTU_TRUST_ROOT_PUBLIC_KEY;
  if (!path || !root) return "UNCONFIRMED";
  try {
    const rootBytes = encodedBytes(root, 32);
    if (!rootBytes) return "UNAUTHORIZED";
    const envelope: unknown = JSON.parse(await readFile(path, "utf8"));
    if (typeof envelope !== "object" || !envelope || Array.isArray(envelope)) return "UNAUTHORIZED";
    const {payload, signature} = envelope as {payload?: unknown; signature?: unknown};
    const sigBytes = encodedBytes(signature, 64);
    if (typeof payload !== "string" || !sigBytes) return "UNAUTHORIZED";
    const key = createPublicKey({key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rootBytes]), format: "der", type: "spki"});
    if (!verify(null, Buffer.from(payload, "utf8"), key, sigBytes)) return "UNAUTHORIZED";
    const manifest: unknown = JSON.parse(payload);
    if (typeof manifest !== "object" || !manifest || Array.isArray(manifest)) return "UNAUTHORIZED";
    const m = manifest as Record<string, unknown>;
    if (m.institution !== "BTU" || m.genesisHash !== input.genesisHash ||
        m.programId !== input.programId || m.configPda !== input.configPda ||
        m.admin !== input.admin || !Array.isArray(m.epochs)) return "UNAUTHORIZED";
    const epoch = m.epochs.find((entry: unknown) =>
      typeof entry === "object" && !!entry && !Array.isArray(entry) &&
      (entry as {number?: unknown}).number === input.epoch &&
      (entry as {issuer?: unknown}).issuer === input.issuer);
    if (!epoch || typeof epoch !== "object") return "UNAUTHORIZED";
    const from = epochTime((epoch as {validFrom?: unknown}).validFrom);
    const untilRaw = (epoch as {validUntil?: unknown}).validUntil;
    const until = untilRaw === null || untilRaw === undefined ? null : epochTime(untilRaw);
    if (from === null || (untilRaw != null && until === null) ||
        input.registeredUnix < from || (until !== null && (until < from || input.registeredUnix > until)))
      return "UNAUTHORIZED";
    return "BTU_CONFIRMED";
  } catch {
    // Missing manifest, malformed JSON, invalid key/signature, unexpected I/O:
    // fail closed. No internal parser errors or filesystem details leave here.
    return "UNAUTHORIZED";
  }
}
