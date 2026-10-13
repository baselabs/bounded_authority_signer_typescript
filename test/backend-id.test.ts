// Every lane asserts which verifier crypto backend it is exercising before it trusts a verdict (design
// M1). Under Node's default conditions the verifier resolves its node:crypto backend; with
// --conditions=bap-portable (pnpm test:portable) it resolves the portable one, so this whole suite runs
// against both. The Deno, Bun and browser lanes assert "portable" on their own.
import { test } from "node:test";
import assert from "node:assert/strict";
import { BACKEND_ID } from "@bounded-authority-protocol/verifier";

// The lane's expectation comes from the flag the lane was started with, never from the module under
// test: --conditions=bap-portable (or -C bap-portable) must resolve the portable backend.
const portableFlag = process.execArgv.some((a, i, all) =>
  a === "--conditions=bap-portable" || a === "-C=bap-portable" ||
  ((a === "--conditions" || a === "-C") && all[i + 1] === "bap-portable"));
const EXPECTED = portableFlag ? "portable" : "node";

test(`the verifier's BACKEND_ID is "${EXPECTED}" in this lane`, () => {
  assert.equal(BACKEND_ID, EXPECTED);
});
