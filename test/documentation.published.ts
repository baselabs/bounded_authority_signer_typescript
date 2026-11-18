// The owning package can be checked in npm only after its upload.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { npmLatest } from "../tools/release-state.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { name: string; version: string };
test("documentation signer identity equals npm latest after upload", () => {
  const env = { ...process.env, npm_config_registry: "https://registry.npmjs.org" };
  assert.equal(pkg.version, npmLatest(pkg.name, { cwd: root, env }));
});
