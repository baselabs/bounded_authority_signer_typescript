// Only signer release identities are registry-currency claims. Protocol majors, dependency
// versions, historical upgrade text and SVG geometry are not signer release identities.
import assert from "node:assert/strict";
import spawn from "cross-spawn";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { parseArgs } from "node:util";

const { values, positionals } = parseArgs({
  options: { source: { type: "string", default: "release" } }, allowPositionals: true,
});
const source = values.source;
assert.ok(source === "release" || source === "commit", "source must be release or commit");
assert.ok(positionals.length <= 1, "expected at most one site root");
const root = positionals[0] ?? process.cwd();
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const run = (command, args) => {
  const result = spawn.sync(command, args, {
    cwd: root, encoding: "utf8", timeout: 90_000, stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, command === "npm"
    ? "could not read npm latest; site version checks fail closed" : `could not read committed package: ${result.stderr}`);
  return result.stdout.trim();
};
let expected, commit;
if (source === "commit") {
  commit = run("git", ["rev-parse", "HEAD"]);
  const committed = JSON.parse(run("git", ["show", `${commit}:package.json`]));
  assert.equal(committed.name, pkg.name);
  expected = committed.version;
} else {
  expected = run("npm", ["view", `${pkg.name}@latest`, "version", "--fetch-retries=1", "--fetch-timeout=20000"]);
  assert.match(expected, /^\d+\.\d+\.\d+$/, "npm latest must be a stable release");
}
const expectation = source === "release" ? `npm latest ${expected}` : `commit ${commit} version ${expected}`;
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const coordinate = `(?:${[pkg.name, pkg.name.replace("/", "+"), encodeURIComponent(pkg.name)].map(escape).join("|")})`;
const version = String.raw`(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)`;
const patterns = [
  new RegExp(coordinate + String.raw`(?:@|%40|\s*(?:-|\()\s*(?:released\s+)?v?)` + version, "gi"),
  new RegExp(String.raw`(?:signer[- ](?:release|version)|released signer)\s*[:=]?\s*v?` + version, "gi"),
];
let pages = 0, claims = 0;
const stale = [];
function record(path, actual) {
  claims++;
  if (actual !== expected) stale.push(`${relative(root, path)}: signer ${actual}`);
}
function check(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) check(path);
    else if (entry.name.endsWith(".html")) {
      pages++;
      const html = readFileSync(path, "utf8");
      for (const pattern of patterns) for (const match of html.matchAll(pattern)) record(path, match[1]);
      // Structured release labels must name this package and an explicit version.
      for (const tag of html.matchAll(/<[^>]+>/g)) {
        const attrs = new Map([...tag[0].matchAll(/([\w-]+)=["']([^"']*)["']/g)].map((m) => [m[1], m[2]]));
        if (attrs.get("data-package") === pkg.name && attrs.has("data-version")) record(path, attrs.get("data-version"));
        if (attrs.get("name") === "signer-version") record(path, attrs.get("content"));
      }
    }
  }
}
const site = join(root, "site-dist");
check(site);
const releaseFile = join(site, "api/release.json");
if (existsSync(releaseFile)) {
  const release = JSON.parse(readFileSync(releaseFile, "utf8"));
  assert.equal(release.package, pkg.name);
  assert.equal(release.version, expected, "API version must match the selected source");
  assert.equal(release.source, source);
  if (source === "commit") {
    assert.equal(release.commit, commit);
    assert.equal(release.tag, undefined, "commit API must not claim a release tag");
  } else assert.equal(release.tag, `v${release.version}`);
}
const documentation = join(site, "api/documentation.json");
if (existsSync(documentation)) {
  assert.equal(JSON.parse(readFileSync(documentation, "utf8")).version, expected,
    "site documentation must target the selected source version");
}
assert.ok(pages > 0, "the built site must contain HTML");
assert.deepEqual(stale, [], `signer release claims must equal ${expectation}`);
console.log(`site badge: PASS (${pages} built pages, ${claims} signer release claims, ${expectation})`);
