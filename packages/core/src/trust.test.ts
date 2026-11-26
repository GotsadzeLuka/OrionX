import {afterEach, describe, expect, it, vi} from "vitest";
import {createPublicKey, generateKeyPairSync, sign} from "node:crypto";
import {mkdtemp, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {issuerTrust} from "./trust";

const ctx = {programId:"synthetic-program",genesisHash:"synthetic-genesis",configPda:"synthetic-config",issuer:"synthetic-issuer",epoch:1,admin:"synthetic-admin",registeredUnix:1000n};
const fixtures: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  for (const file of fixtures.splice(0)) await rm(file, {recursive:true,force:true});
});

async function fixture(modify?: (manifest: Record<string, unknown>)=>void) {
  const {publicKey, privateKey} = generateKeyPairSync("ed25519");
  const dir = await mkdtemp(join(tmpdir(),"orionx-trust-"));
  fixtures.push(dir);
  const manifest: Record<string, unknown> = {
    institution:"BTU", genesisHash:ctx.genesisHash, programId:ctx.programId,
    configPda:ctx.configPda, admin:ctx.admin,
    epochs:[{number:1,issuer:ctx.issuer,validFrom:900,validUntil:1100}],
  };
  modify?.(manifest);
  const payload = JSON.stringify(manifest);
  const path=join(dir,"trust.json");
  await writeFile(path,JSON.stringify({payload,signature:sign(null,Buffer.from(payload),privateKey).toString("base64")}));
  const raw=publicKey.export({format:"der",type:"spki"}).subarray(-32).toString("base64");
  vi.stubEnv("BTU_TRUST_MANIFEST_PATH",path);
  vi.stubEnv("BTU_TRUST_ROOT_PUBLIC_KEY",raw);
  vi.stubEnv("ISSUER_TRUST_MODE","");
  return {path,raw};
}

describe("institutional issuer trust is fail closed",() => {
  it("distinguishes demo from unconfigured institutional evidence", async () => {
    vi.stubEnv("ISSUER_TRUST_MODE","DEMO");
    expect(await issuerTrust(ctx)).toBe("DEMO");
    vi.stubEnv("ISSUER_TRUST_MODE","");
    vi.stubEnv("BTU_TRUST_MANIFEST_PATH","");
    vi.stubEnv("BTU_TRUST_ROOT_PUBLIC_KEY","");
    expect(await issuerTrust(ctx)).toBe("UNCONFIRMED");
  });
  it("accepts only a valid signed manifest pinned to all chain identities and epoch", async () => {
    await fixture();
    expect(await issuerTrust(ctx)).toBe("BTU_CONFIRMED");
    expect(await issuerTrust({...ctx,issuer:"another"})).toBe("UNAUTHORIZED");
    expect(await issuerTrust({...ctx,genesisHash:"another"})).toBe("UNAUTHORIZED");
    expect(await issuerTrust({...ctx,registeredUnix:1200n})).toBe("UNAUTHORIZED");
  });
  it("rejects malformed JSON, missing files, invalid root and tampered signatures", async () => {
    const {path,raw}=await fixture();
    vi.stubEnv("BTU_TRUST_ROOT_PUBLIC_KEY",Buffer.alloc(32,1).toString("base64"));
    expect(await issuerTrust(ctx)).toBe("UNAUTHORIZED");
    vi.stubEnv("BTU_TRUST_ROOT_PUBLIC_KEY",raw);
    await writeFile(path,"not-json");
    expect(await issuerTrust(ctx)).toBe("UNAUTHORIZED");
    vi.stubEnv("BTU_TRUST_MANIFEST_PATH",path+".missing");
    expect(await issuerTrust(ctx)).toBe("UNAUTHORIZED");
  });
  it("accepts valid epoch bounds encoded as integer strings", async () => {
    await fixture(m=>{m.epochs=[{number:1,issuer:ctx.issuer,validFrom:"900",validUntil:"1100"}]});
    expect(await issuerTrust(ctx)).toBe("BTU_CONFIRMED");
  });
  it("does not allow invalid or missing epoch time bounds to grant trust", async () => {
    await fixture(m=>{m.epochs=[{number:1,issuer:ctx.issuer,validFrom:"garbage"}]});
    expect(await issuerTrust(ctx)).toBe("UNAUTHORIZED");
  });
});
