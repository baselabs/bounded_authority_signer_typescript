// WebCrypto key handles on Node (pnpm test, on Node 22.23.1 and 24.19.0; pnpm test:portable under the
// verifier's portable backend). Runs the shared battery (test/lanes/webcrypto.ts, the same one the Deno,
// Bun and browser lanes run) with one node:test per check, and adds the Node-only rows: T4b's expected
// value on Node, and the R3 evidence that on Node a non-extractable private key is exportable by any code
// in the process through KeyObject.from(). Real keys from Node's own WebCrypto; no mocks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { KeyObject } from "node:crypto";
import { runWebCryptoLane, type WebCryptoLaneReport } from "./lanes/webcrypto.js";
import { edPair, ecPair } from "./lanes/webcrypto-keys.js";

let report: WebCryptoLaneReport;
test.before(async () => {
  report = await runWebCryptoLane();
});

test("the battery ran its rows", (t) => {
  const n = Object.keys(report.checks).length;
  assert.ok(n >= 90, `${n} checks`);
  t.diagnostic(`node ${process.version}: ${n} checks; capability ${JSON.stringify(report.capability)}; T4b ${report.observed.proxySymbolFlip}`);
});

test("every battery check holds", () => {
  const failed = Object.entries(report.checks).filter(([, v]) => !v).map(([k]) => k);
  assert.deepEqual(failed, []);
});

test("capability: Node generates Ed25519 and P-256 keys and signs 64-byte raw signatures", () => {
  assert.equal(report.capability.ed25519Generate, true);
  assert.equal(report.capability.ecdsaP256Generate, true);
  assert.equal(report.capability.es256SignWidth, 64);
  assert.equal(report.capability.ed25519SignWidth, 64);
  assert.equal(report.capability.ecdsaDeterministic, false, "Node's ECDSA is randomized");
});

test("T4b on Node: a symbol-flipping Proxy over an extractable private key is invalid_key_handle", () => {
  // Node 22 throws inside the getter (a Proxy invariant on its non-configurable internal symbol);
  // Node 24's getter refuses the Proxy outright. Either way the factory refuses.
  assert.equal(report.observed.proxySymbolFlip, "error:invalid_key_handle");
});

test("R3 on Node: KeyObject.from() exports a NON-extractable private key (any code in the process can)", async () => {
  // The README's claim, observed: non-extractable is a browser property only. This is why the handles
  // never claim to keep a key from code running in the same Node or Bun process.
  const ed = await edPair(false);
  const ec = await ecPair(false);
  assert.equal(ed.privateKey.extractable, false);
  const fromEd = KeyObject.from(ed.privateKey as never).export({ format: "jwk" }) as { d?: string };
  const fromEc = KeyObject.from(ec.privateKey as never).export({ format: "der", type: "pkcs8" });
  assert.equal(typeof fromEd.d, "string");
  assert.ok(fromEc.length > 0);
});
