#!/usr/bin/env node
// Builds the package tarball that is checked and published (pnpm pack:release; test:tarball,
// test/reader.ts and the release workflow all use it). Run `pnpm build` first.
//
// It packs the repository with npm, scripts ignored, into an output directory, and never writes the
// working tree. npm packs with fixed file times and order, so the same tree gives the same bytes: the
// release job compares the SHA-256 of its tarball with the one the verify job checked, and then
// publishes that file (`npm stage publish <file>`, which runs no scripts and reads the manifest from
// the tarball). The same model as the verifier repository's tools/pack.mjs, without its staging copy:
// this manifest carries no development-only conditions to strip.
//
// Usage: node tools/pack.mjs [--out <dir>]   Prints {"file": <absolute path>, "sha256": <hex>}.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

export function pack(outDir) {
  if (!existsSync(join(ROOT, "dist/src/index.js"))) throw new Error("dist/src/index.js is missing: run pnpm build first");
  mkdirSync(outDir, { recursive: true });
  const out = execFileSync("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", outDir], {
    cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  });
  const [packed] = JSON.parse(out);
  const file = join(outDir, packed.filename);
  const sha256 = createHash("sha256").update(readFileSync(file)).digest("hex");
  return { file, sha256 };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const at = process.argv.indexOf("--out");
  const outDir = resolve(at > 0 && process.argv[at + 1] ? process.argv[at + 1] : join(ROOT, "build-pack"));
  console.log(JSON.stringify(pack(outDir)));
}
