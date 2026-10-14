// The runtime lanes (pnpm test:runtimes): each runtime runs test/lanes/runtime.ts from the repository.
// The verifier package resolves its "#crypto" import under the runtime's own conditions: Node's default
// conditions select the node backend; --conditions=bap-portable on Node, and Deno and Bun (their deno and
// bun conditions), select the portable one. Each lane asserts BACKEND_ID before any check, then runs the
// L2/L3 battery; this test holds every check true and red-proofs the backend assertion.
// BAP_RUNTIMES selects the lanes (default "node,node-portable,deno,bun").
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const ENTRY = "test/lanes/runtime.ts";
const LANES: Record<string, { expect: "node" | "portable"; wrong: "node" | "portable"; command: (expect: string) => string[] }> = {
  node: { expect: "node", wrong: "portable", command: (e) => [process.execPath, "--import", "tsx/esm", ENTRY, `--expect=${e}`] },
  "node-portable": { expect: "portable", wrong: "node", command: (e) => [process.execPath, "--conditions=bap-portable", "--import", "tsx/esm", ENTRY, `--expect=${e}`] },
  deno: { expect: "portable", wrong: "node", command: (e) => ["deno", "run", "--sloppy-imports", "--allow-read", "--allow-env", ENTRY, `--expect=${e}`] },
  bun: { expect: "portable", wrong: "node", command: (e) => ["bun", ENTRY, `--expect=${e}`] },
};
const SELECTED = (process.env.BAP_RUNTIMES ?? "node,node-portable,deno,bun").split(",").filter(Boolean);

// Per-lane expectations for the WebCrypto key-handle battery (design §12.3 and §12.7, revisions R1 and R3).
// T4b: a Proxy that flips every symbol-keyed true to false defeats the CryptoKey getter only on Deno,
// whose internal slots are symbol properties read through the Proxy (and whose subtle.sign accepts the
// Proxy), so there the factory accepts an extractable key: a recorded exception. The getter read is a
// guard against accidents, never against the key's own holder. R3: KeyObject.from() exports a
// non-extractable private key on Node and Bun; Deno refuses.
const T4B: Record<string, string> = { node: "error:invalid_key_handle", "node-portable": "error:invalid_key_handle", deno: "ok", bun: "error:invalid_key_handle" };
const KEY_OBJECT_EXPORT: Record<string, RegExp> = { node: /^exported$/, "node-portable": /^exported$/, deno: /^refused:/, bun: /^exported$/ };

const runs = new Map<string, SpawnSyncReturns<string>>();
function run(lane: string, expect: string) {
  const memo = runs.get(`${lane}:${expect}`);
  if (memo !== undefined) return memo; // one lane process serves both the L2 and the key-handle test
  const [cmd, ...args] = LANES[lane]!.command(expect);
  const r = spawnSync(cmd!, args, { cwd: REPO, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (r.error) throw r.error;
  runs.set(`${lane}:${expect}`, r);
  return r;
}

for (const lane of SELECTED) {
  const spec = LANES[lane];
  assert.ok(spec, `known lane ${lane}`);

  test(`${lane}: BACKEND_ID is ${spec.expect}, and v1, v2 and v3 sign then verify (L2) with low-S holding (L3)`, (t) => {
    const r = run(lane, spec.expect);
    assert.equal(r.status, 0, r.stderr || r.stdout);
    const report = JSON.parse(r.stdout) as { runtime: string; backend: string; ok: boolean; ms: number; checks: Record<string, boolean>; trials: number; highS: number };
    assert.equal(report.backend, spec.expect);
    assert.ok(report.runtime.startsWith(lane.startsWith("node") ? "node" : lane), report.runtime);
    const failed = Object.entries(report.checks).filter(([, v]) => !v).map(([k]) => k);
    assert.deepEqual(failed, []);
    assert.ok(Object.keys(report.checks).length >= 23, `${Object.keys(report.checks).length} checks`);
    assert.ok(report.highS > 0, "the L3 sample contains high-S raw signatures");
    assert.equal(report.ok, true);
    t.diagnostic(`${report.runtime} (backend ${report.backend}): ${Object.keys(report.checks).length} checks, ${report.trials} v3 trials, ${report.highS} high-S normalized, ${report.ms} ms`);
  });

  test(`${lane}: WebCrypto key handles with the runtime's own non-extractable keys (T1-T10, T12, R13), T4b and R3 as recorded for this runtime`, (t) => {
    const r = run(lane, spec.expect);
    assert.equal(r.status, 0, r.stderr || r.stdout);
    const report = JSON.parse(r.stdout) as {
      runtime: string;
      webcrypto: { checks: Record<string, boolean>; capability: Record<string, unknown>; observed: { proxySymbolFlip: string } };
      keyObjectExport: string;
    };
    const failed = Object.entries(report.webcrypto.checks).filter(([, v]) => !v).map(([k]) => k);
    assert.deepEqual(failed, []);
    assert.ok(Object.keys(report.webcrypto.checks).length >= 90, `${Object.keys(report.webcrypto.checks).length} checks`);
    assert.equal(report.webcrypto.capability.ed25519Generate, true, "the engine generates Ed25519 keys (never skipped)");
    assert.equal(report.webcrypto.capability.ecdsaP256Generate, true);
    assert.equal(report.webcrypto.observed.proxySymbolFlip, T4B[lane], "T4b");
    assert.match(report.keyObjectExport, KEY_OBJECT_EXPORT[lane]!, "R3");
    t.diagnostic(`${report.runtime}: ${Object.keys(report.webcrypto.checks).length} key-handle checks; T4b ${report.webcrypto.observed.proxySymbolFlip}; KeyObject.from ${report.keyObjectExport}; capability ${JSON.stringify(report.webcrypto.capability)}`);
  });

  test(`${lane}: red-proof: the lane fails, running no check, when it expects the wrong backend`, () => {
    const r = run(lane, spec.wrong);
    assert.equal(r.status, 1);
    assert.match(r.stderr, new RegExp(`BACKEND_ID is "${spec.expect}", this lane expects "${spec.wrong}"; no check was run`));
    assert.equal(r.stdout.trim(), "");
  });
}
