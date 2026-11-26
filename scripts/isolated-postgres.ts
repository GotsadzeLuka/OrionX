import {spawnSync} from "node:child_process";
import {readdir, readFile, writeFile} from "node:fs/promises";
import {resolve} from "node:path";

export function requireIsolatedPostgres(): string {
  const {ORIONX_ISOLATED_TEST, DATABASE_URL, DIRECT_URL} = process.env;
  const urls = [DATABASE_URL, DIRECT_URL].filter((value): value is string => Boolean(value));
  if (ORIONX_ISOLATED_TEST !== "1" || !DATABASE_URL || !urls.every(value => {
    const url = new URL(value);
    return ["postgres:", "postgresql:"].includes(url.protocol) && ["localhost", "127.0.0.1"].includes(url.hostname);
  })) throw new Error("Set ORIONX_ISOLATED_TEST=1 and disposable loopback PostgreSQL URLs.");
  return DIRECT_URL || DATABASE_URL;
}

export async function applyIsolatedMigrations(url: URL, directory: string) {
  const schema = url.searchParams.get("schema");
  if (!schema || !/^(worker_crash|revocation|orionx_load)_[a-f0-9]+$/.test(schema)) {
    throw new Error("Invalid isolated migration schema");
  }
  const folder = resolve("packages/db/prisma/migrations");
  const entries = await readdir(folder, {withFileTypes: true});
  const names = entries.filter(item => item.isDirectory()).map(item => item.name).sort();
  const migrations = await Promise.all(names.map(async name =>
    (await readFile(resolve(folder, name, "migration.sql"), "utf8"))
      .replace("REVOKE EXECUTE ON FUNCTION public.rls_auto_enable() FROM PUBLIC, anon, authenticated;", "")
      .replaceAll("public.", `"${schema}".`),
  ));
  const setup = `
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN; END IF;
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
    END $$;
    CREATE SCHEMA IF NOT EXISTS "${schema}";
    SET search_path TO "${schema}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA "${schema}" GRANT EXECUTE ON FUNCTIONS TO anon, authenticated;
  `;
  const file = resolve(directory, "setup.sql");
  await writeFile(file, setup + migrations.join("\n"));
  const execution = spawnSync(process.execPath, [
    "node_modules/prisma/build/index.js", "db", "execute", "--schema", "packages/db/prisma/schema.prisma", "--file", file,
  ], {
    env: {...process.env, DATABASE_URL: url.href, DIRECT_URL: url.href},
    encoding: "utf8",
    timeout: 30_000,
  });
  if (execution.status !== 0) {
    throw new Error("Isolated migrations failed: " + (execution.stderr || execution.error?.message || execution.status));
  }
}
