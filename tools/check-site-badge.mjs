// The playground page's npm badge (web/index.html, `<li>npm X.Y.Z</li>`) is a hand-maintained literal.
// It passes when it names
//   - the latest version of this package on the npm registry, or
//   - package.json's version while a v<version> tag points at HEAD: the release commit, whose Pages
//     deploy runs before the npm publish is approved (0.3.1, 0.4.0 and 0.5.0 all did). This state needs
//     no registry call. If the tag is pushed after the commit, rerun the Pages job once it is.
// Anything else fails: a badge ahead of npm without a release tag claims a version nobody can install,
// and a badge behind npm is stale.
// Registry outage: fail closed. The check exists to keep a false version claim off the page, and
// without the registry it cannot tell a stale badge from a current one; skipping would let exactly that
// through. A failed docs deploy costs a rerun; nothing else depends on it.
// Usage: node tools/check-site-badge.mjs [repository root]   (exit 0 pass, 1 fail)
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { npmLatest, tagAtHead } from "./release-state.mjs";

const root = process.argv[2] ?? process.cwd();
const pass = (message) => { console.log(`site badge: PASS (${message})`); process.exit(0); };
const fail = (message) => { console.error(`site badge: FAIL: ${message}`); process.exit(1); };

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const html = readFileSync(join(root, "web/index.html"), "utf8");
const badges = [...html.matchAll(/<li>npm ([0-9]+\.[0-9]+\.[0-9]+)<\/li>/g)].map((m) => m[1]);
if (badges.length !== 1) fail(`web/index.html must carry exactly one <li>npm X.Y.Z</li> badge; found ${badges.length}`);
const badge = badges[0];

if (badge === pkg.version && tagAtHead(badge, { cwd: root })) {
  pass(`names ${badge}, package.json's version, and v${badge} points at HEAD: a release commit`);
}

let latest;
try {
  latest = npmLatest(pkg.name, { cwd: root });
} catch (error) {
  fail(`could not read the latest ${pkg.name} version from the npm registry (${String(error.message).split("\n")[0]}). ` +
    "The badge cannot be checked without it; rerun this job once the registry answers.");
}
if (badge === latest) pass(`names ${badge}, the latest npm release`);
fail(badge === pkg.version
  ? `names ${badge}, package.json's version, which is not on npm (latest ${latest}) and has no v${badge} tag at HEAD; name ${latest} until ${badge} is released`
  : `names ${badge}, but the latest npm release is ${latest}; update the badge`);
