import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { name: string };
const script = join(root, "tools/check-site-badge.mjs");

test("signer release identities fail closed; protocol, dependency and historical versions are allowed", () => {
  const scratch = mkdtempSync(join(tmpdir(), "bap-site-badge-"));
  try {
    writeFileSync(join(scratch, "package.json"), JSON.stringify({ name: pkg.name, version: "99.0.0" }));
    mkdirSync(join(scratch, "site-dist/api"), { recursive: true });
    const run = (registry?: string) => {
      const env = { ...process.env };
      if (registry !== undefined) env.npm_config_registry = registry;
      const result = spawnSync(process.execPath, [script, scratch], { cwd: root, env, encoding: "utf8", timeout: 120_000 });
      assert.ifError(result.error);
      return { status: result.status, output: result.stdout + result.stderr };
    };
    const home = join(scratch, "site-dist/index.html");
    const nested = join(scratch, "site-dist/api/index.html");
    writeFileSync(home, '<li>Development source</li><p>http://127.0.0.1</p><svg><path d="M8 21v-2c0-1.1.9-2 2-2h4"/></svg>');
    writeFileSync(nested, "<aside>node_modules/.pnpm/typescript@6.0.3/node_modules/typescript/lib.d.ts</aside><p>Protocol 3.0.0; previous package 1.0.0; Python 3.13.9</p>");
    let result = run();
    assert.equal(result.status, 0, result.output);
    const latest = /npm latest (\d+\.\d+\.\d+)/.exec(result.output)?.[1];
    assert.ok(latest, result.output);
    writeFileSync(nested, `<header>released v${latest}</header><footer>${pkg.name}@${latest}.</footer>`);
    result = run();
    assert.equal(result.status, 0, result.output);
    for (const claim of [
      `<p>${pkg.name}@99.0.0</p>`, `<title>${pkg.name} - v99.0.0</title>`,
      `<header>${pkg.name} (released v99.0.0)</header>`, '<meta name="signer-version" content="99.0.0">',
      '<p>signer version 99.0.0-beta.1</p>', `<div data-version="99.0.0" data-package="${pkg.name}"></div>`,
      `<aside>node_modules/.pnpm/${pkg.name.replace("/", "+")}@99.0.0/node_modules/sdk/index.d.ts</aside>`]) {
      writeFileSync(nested, claim);
      result = run();
      assert.equal(result.status, 1, result.output);
      assert.match(result.output, /site-dist[\/\\]api[\/\\]index.html: signer 99\.0\.0/);
    }
    writeFileSync(nested, "<p>API</p>");
    execFileSync("git", ["init", "-q", scratch]);
    execFileSync("git", ["-c", "user.name=badge-test", "-c", "user.email=badge-test@example.invalid", "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "fixture"], { cwd: scratch });
    execFileSync("git", ["-c", "tag.gpgsign=false", "tag", "v99.0.0"], { cwd: scratch });
    writeFileSync(home, `<li>Development source</li><li>${pkg.name}@99.0.0</li>`);
    result = run();
    assert.equal(result.status, 1, result.output);
    writeFileSync(home, "<li>Development source</li>");
    result = run("http://127.0.0.1:9/");
    assert.equal(result.status, 1, result.output);
    assert.match(result.output, /could not read npm latest/);
    console.log("Rejected planted badge, header, footer, package, metadata and prerelease claims; rejected a tagged unpublished claim and a real registry outage.");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
