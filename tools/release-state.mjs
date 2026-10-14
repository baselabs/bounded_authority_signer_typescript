// Release state, read from the real sources: the npm registry's latest version of a package, and
// whether a v<version> tag points at HEAD (locally, or on the origin remote, so a shallow CI checkout
// without tags still sees it). Used by tools/check-site-badge.mjs and test/reader.ts.
import { execFileSync } from "node:child_process";

const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+$/;

/** The latest version of `name` on the registry npm is configured for. Throws when the registry does not answer. */
export function npmLatest(name, { cwd = process.cwd(), env = process.env } = {}) {
  const out = execFileSync("npm", ["view", name, "version", "--fetch-retries=1", "--fetch-timeout=20000"], {
    cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 90_000,
  }).trim();
  if (!SEMVER.test(out)) throw new Error(`npm view ${name} version returned ${JSON.stringify(out)}`);
  return out;
}

const git = (args, cwd) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60_000 }).trim();

/** Whether the tag v<version> points at HEAD, checked locally and then on origin. Never throws. */
export function tagAtHead(version, { cwd = process.cwd() } = {}) {
  const tag = `v${version}`;
  let head;
  try {
    head = git(["rev-parse", "HEAD"], cwd);
  } catch {
    return false;
  }
  try {
    if (git(["tag", "--points-at", "HEAD"], cwd).split("\n").includes(tag)) return true;
  } catch {
    // no local tags; fall through to the remote
  }
  try {
    const lines = git(["ls-remote", "--tags", "origin", `refs/tags/${tag}`, `refs/tags/${tag}^{}`], cwd);
    return lines.split("\n").some((line) => line.split("\t")[0] === head);
  } catch {
    return false;
  }
}
