// The Quickstart as a reader runs it, outside this repository: an empty directory, the README's setup
// commands run verbatim with npm, the README's key-handle.ts and quickstart.ts written as shown, then
// `npx tsx quickstart.ts`, whose output must match the README. The packages come from the npm registry at
// the versions the README pins; only when the README pins this repository's own (not yet published)
// version is the signer replaced by this repository's packed tarball (the release commit, before the
// publish). A second test checks the pins: the signer version is npm's latest (or package.json's version
// with a v<version> tag at HEAD), the verifier version is npm's latest and inside this package's
// dependency range, and every mention agrees. Needs the network (pnpm test:tarball runs it, after a build).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { npmLatest, tagAtHead } from "../tools/release-state.mjs";
import { parse } from "./readme-samples.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const README = readFileSync(join(REPO, "README.md"), "utf8");
const MANIFEST = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as { name: string; version: string; dependencies: Record<string, string> };
const SIGNER = "@bounded-authority-protocol/signer";
const VERIFIER = "@bounded-authority-protocol/verifier";

/** Whether `version` is inside a caret range `^X.Y.Z` (before 1.0 the minor is the breaking boundary). */
function inCaretRange(version: string, range: string): boolean {
  const m = /^\^([0-9]+)\.([0-9]+)\.([0-9]+)$/.exec(range);
  assert.ok(m, `the dependency range ${range} is a caret range`);
  const [x, y, z] = m.slice(1).map(Number) as [number, number, number];
  const [a, b, c] = version.split(".").map(Number) as [number, number, number];
  if (a !== x) return false;
  if (x === 0) return b === y && c >= z;
  return b > y || (b === y && c >= z);
}

const pins = (name: string): string[] => [...README.matchAll(new RegExp(`${name.replace("/", "\\/")}@([0-9]+\\.[0-9]+\\.[0-9]+)`, "g"))].map((m) => m[1]!);

/** The environment a reader's shell has: this one without the npm and pnpm variables a pnpm script sets. */
function readerEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^(npm|pnpm)_/i.test(key) || key === "NODE_OPTIONS") delete env[key];
  return env;
}

test("README pins: the signer is npm's latest (or the release-tagged package.json version), the verifier npm's latest within range", () => {
  const signer = [...new Set(pins(SIGNER))];
  const verifier = [...new Set(pins(VERIFIER))];
  assert.equal(signer.length, 1, `the README pins one signer version, found ${JSON.stringify(signer)}`);
  assert.equal(verifier.length, 1, `the README pins one verifier version, found ${JSON.stringify(verifier)}`);
  const latestSigner = npmLatest(SIGNER);
  const released = signer[0] === MANIFEST.version && tagAtHead(MANIFEST.version, { cwd: REPO });
  assert.ok(signer[0] === latestSigner || released,
    `the README pins ${SIGNER}@${signer[0]}; npm's latest is ${latestSigner}` +
    (signer[0] === MANIFEST.version ? ` and no v${MANIFEST.version} tag points at HEAD` : ""));
  assert.equal(verifier[0], npmLatest(VERIFIER), `the README pins ${VERIFIER}@${verifier[0]}, which is not npm's latest`);
  assert.ok(inCaretRange(verifier[0]!, MANIFEST.dependencies[VERIFIER]!), `${verifier[0]} is outside the dependency range ${MANIFEST.dependencies[VERIFIER]}`);
});

test("README Quickstart: an empty directory, the setup commands, the two files, npx tsx: prints the output shown", () => {
  const samples = parse(README);
  const setup = samples.filter((s) => s.kind === "setup");
  assert.equal(setup.length, 1, "the README has one setup block");
  const helper = samples.find((s) => s.kind === "file" && s.fileName === "key-handle.ts");
  assert.ok(helper, "the README has key-handle.ts");
  const quickstart = samples.find((s) => s.kind === "run" && s.line > helper.line);
  assert.ok(quickstart?.output !== undefined, "the Quickstart is the first run sample after key-handle.ts, with its output");

  const dir = mkdtempSync(join(tmpdir(), "bap-reader-"));
  try {
    let commands = setup[0]!.code;
    const pinned = pins(SIGNER)[0];
    if (pinned === MANIFEST.version) {
      // The README pins this source's version: install the packed tarball (pnpm test:tarball builds first).
      execFileSync("pnpm", ["pack", "--pack-destination", dir], { cwd: REPO, stdio: "pipe" });
      const tarball = readdirSync(dir).find((f) => f.endsWith(".tgz"));
      assert.ok(tarball);
      commands = commands.replaceAll(`${SIGNER}@${pinned}`, join(dir, tarball));
    }
    const project = join(dir, "reader");
    execFileSync("mkdir", [project]);
    const env = readerEnv();
    const sh = spawnSync("bash", ["-e", "-c", commands], { cwd: project, env, encoding: "utf8", timeout: 300_000 });
    assert.equal(sh.status, 0, `the setup commands failed:\n${sh.stdout}\n${sh.stderr}`);
    writeFileSync(join(project, "key-handle.ts"), helper.code + "\n");
    writeFileSync(join(project, "quickstart.ts"), quickstart.code + "\n");
    const r = spawnSync("npx", ["tsx", "quickstart.ts"], { cwd: project, env, encoding: "utf8", timeout: 120_000 });
    assert.equal(r.status, 0, `npx tsx quickstart.ts failed:\n${r.stdout}\n${r.stderr}`);
    assert.equal(r.stdout.trimEnd(), quickstart.output);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
