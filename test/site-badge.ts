// tools/check-site-badge.mjs on real substrates: real git repositories (a bare origin and a clone with or
// without a release tag at HEAD), the real npm registry, and an unreachable registry for the outage. Each
// case writes a package.json and a web/index.html badge and runs the script as the Pages workflow does.
// Needs the network (pnpm test:tarball runs it).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { npmLatest } from "../tools/release-state.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const SCRIPT = join(REPO, "tools/check-site-badge.mjs");
const NAME = "@bounded-authority-protocol/signer";
const UNRELEASED = "99.0.0"; // a version the registry does not have
const OUTAGE = "http://127.0.0.1:9/"; // nothing listens on the discard port

function scratch(): string {
  return mkdtempSync(join(tmpdir(), "bap-site-badge-"));
}

const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", ["-c", "user.name=badge-test", "-c", "user.email=badge-test@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", ...args], { cwd, stdio: "pipe" });

/** A clone of a bare origin holding package.json and the badge; `tag` places v<version> on HEAD, on the previous commit, or nowhere. */
function repo(dir: string, opts: { version: string; badge: string; tag: "none" | "head" | "previous" }): string {
  const origin = join(dir, "origin.git");
  const work = join(dir, "work");
  git(dir, "init", "-q", "--bare", origin);
  git(dir, "clone", "-q", origin, work);
  writeFileSync(join(work, "package.json"), JSON.stringify({ name: NAME, version: opts.version }));
  mkdirSync(join(work, "web"));
  writeFileSync(join(work, "web/index.html"), "<ul>\n  <li>other</li>\n</ul>\n");
  git(work, "add", ".");
  git(work, "commit", "-q", "-m", "first");
  if (opts.tag === "previous") git(work, "tag", `v${opts.version}`);
  writeFileSync(join(work, "web/index.html"), `<ul>\n  <li>npm ${opts.badge}</li><li>CI</li>\n</ul>\n`);
  git(work, "add", ".");
  git(work, "commit", "-q", "-m", "badge");
  if (opts.tag === "head") git(work, "tag", `v${opts.version}`);
  git(work, "push", "-q", "origin", "HEAD", "--tags");
  // A fresh shallow clone with no tags, like actions/checkout: the tag can only be seen on origin.
  const shallow = join(dir, "checkout");
  git(dir, "clone", "-q", "--depth", "1", "--no-tags", `file://${origin}`, shallow);
  return shallow;
}

function run(cwd: string, registry?: string): { status: number | null; output: string } {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^(npm|pnpm)_/i.test(key)) delete env[key];
  if (registry !== undefined) env.npm_config_registry = registry;
  const r = spawnSync(process.execPath, [SCRIPT, cwd], { cwd, env, encoding: "utf8", timeout: 120_000 });
  return { status: r.status, output: `${r.stdout}${r.stderr}` };
}

function check(opts: { version: string; badge: string; tag: "none" | "head" | "previous" }, registry?: string) {
  const dir = scratch();
  try {
    return run(repo(dir, opts), registry);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const LATEST = npmLatest(NAME);

test("site badge: between a version bump and its release, the badge names the latest npm release: pass", () => {
  const r = check({ version: UNRELEASED, badge: LATEST, tag: "none" });
  assert.equal(r.status, 0, r.output);
  assert.match(r.output, /the latest npm release/);
});

test("site badge: a badge naming the unreleased package.json version, with no release tag, fails", () => {
  const r = check({ version: UNRELEASED, badge: UNRELEASED, tag: "none" });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /not on npm .* no v99\.0\.0 tag at HEAD/);
});

test("site badge: a release commit (v<version> at HEAD on origin, seen from a shallow clone) passes before the publish", () => {
  const r = check({ version: UNRELEASED, badge: UNRELEASED, tag: "head" });
  assert.equal(r.status, 0, r.output);
  assert.match(r.output, /a release commit/);
});

test("site badge: a release tag on an earlier commit does not count", () => {
  const r = check({ version: UNRELEASED, badge: UNRELEASED, tag: "previous" });
  assert.equal(r.status, 1, r.output);
});

test("site badge: a stale badge (behind npm) fails", () => {
  const r = check({ version: LATEST, badge: "0.0.1", tag: "none" });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /update the badge/);
});

test("site badge: registry outage fails closed with a clear message", () => {
  const r = check({ version: UNRELEASED, badge: LATEST, tag: "none" }, OUTAGE);
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /could not read the latest .* from the npm registry .* rerun this job/);
});

test("site badge: a release commit passes during a registry outage (no registry call needed)", () => {
  const r = check({ version: UNRELEASED, badge: UNRELEASED, tag: "head" }, OUTAGE);
  assert.equal(r.status, 0, r.output);
});
