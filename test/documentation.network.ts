// Published dependency pins remain registry checks during candidate qualification.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { npmLatest } from "../tools/release-state.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  name: string; version: string; dependencies: Record<string, string>;
};
test("documentation verifier dependency equals npm latest", () => {
  const env = { ...process.env, npm_config_registry: "https://registry.npmjs.org" };
  const verifier = "@bounded-authority-protocol/verifier";
  assert.equal(pkg.dependencies[verifier]!.replace(/^[~^]/, ""), npmLatest(verifier, { cwd: root, env }));
});
