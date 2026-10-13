// The strict ES256 post-sign check. The v3 signing tail is sign -> normalizeLowS -> strict verify ->
// assemble, and the verify step is the verifier package's es256VerifyStrict (the ES256 sibling of
// verifyStrict): it refuses a high-S signature, so a missed or broken low-S normalization fails closed
// as signing_failed instead of emitting a malleable signature. normalizeLowS refuses r or s outside
// (0, n) before it normalizes, and the tail maps that refusal to signing_failed.
//
//   s1. normalizeLowS range asserts: r = 0, r = n, s = 0, s = n, s = n + 1 each throw.
//   s2. a handle returning any of those values gets signing_failed from signV3Report.
//   s3. the post-sign check refuses the high-S twin of a valid signature (strict, not the backend).
//   s4. mutation: with normalizeLowS replaced by the identity (in a copy of src/), signV3Report returns
//       signing_failed for every trial whose raw signature was high-S, and succeeds otherwise.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sign as ecSign, verify as ecVerify, createPublicKey } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { P256_HALF_ORDER, P256_ORDER, es256Verifies, normalizeLowS } from "../src/es256.js";
import { signV3Grant, signV3Report, type Es256KeyHandle } from "../src/index.js";
import { amountArgs, ecHandleFor, ecRawKey, type EcRawKey } from "./helpers.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const AUDIENCE = "https://resource.example.test";
const INVOCATION_ID = "550e8400-e29b-41d4-a716-446655440000";

const bigIntTo32 = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};
const bytesToBigInt = (bytes: Uint8Array): bigint => {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
};
const rs = (r: bigint, s: bigint): Uint8Array => {
  const out = new Uint8Array(64);
  out.set(bigIntTo32(r), 0);
  out.set(bigIntTo32(s), 32);
  return out;
};

const OUT_OF_RANGE: ReadonlyArray<readonly [string, bigint, bigint]> = [
  ["r = 0", 0n, 1n],
  ["r = n", P256_ORDER, 1n],
  ["r = n + 1", P256_ORDER + 1n, 1n],
  ["s = 0", 1n, 0n],
  ["s = n", 1n, P256_ORDER],
  ["s = n + 1", 1n, P256_ORDER + 1n],
];

for (const [label, r, s] of OUT_OF_RANGE) {
  test(`s1: normalizeLowS refuses ${label}`, () => {
    assert.throws(() => normalizeLowS(rs(r, s)));
  });
}

test("s1: normalizeLowS still accepts the in-range edges (r = 1, s = 1, s = n - 1, s = (n-1)/2)", () => {
  assert.deepEqual(normalizeLowS(rs(1n, 1n)), rs(1n, 1n));
  assert.deepEqual(normalizeLowS(rs(P256_ORDER - 1n, P256_HALF_ORDER)), rs(P256_ORDER - 1n, P256_HALF_ORDER));
  assert.deepEqual(normalizeLowS(rs(1n, P256_ORDER - 1n)), rs(1n, 1n));
});

async function fixtureGrant(holder: EcRawKey): Promise<Uint8Array> {
  const issuer = ecRawKey();
  const g = await signV3Grant({
    issuer: "https://issuer.example.test", grantId: "urn:example:grant:s", audiences: [AUDIENCE],
    issuedAt: 1000, notBefore: 1000, expiresAt: 2000, holderThumbprint: holder.thumbprint,
    operations: [{ name: "transfer", selectors: [{ kind: "all" }] as never }],
  }, ecHandleFor(issuer, { keyId: "issuer-key", role: "issuer" }));
  if (!g.ok) throw new Error("fixture grant signing failed");
  return g.value.grant;
}

const report = (grantCompact: Uint8Array) => ({
  grantCompact, operation: "transfer", method: "POST", targetUri: `${AUDIENCE}/invoke`,
  invocationId: INVOCATION_ID, castArguments: amountArgs(),
});

for (const [label, r, s] of OUT_OF_RANGE) {
  test(`s2: a handle returning ${label} gets signing_failed`, async () => {
    const holder = ecRawKey();
    const grant = await fixtureGrant(holder);
    const handle: Es256KeyHandle = { sign: () => rs(r, s), publicKey: () => holder.publicKey, thumbprint: () => holder.thumbprint };
    const result = await signV3Report(report(grant), handle, { issuedAt: 1500, proofId: "urn:example:proof:s2" });
    assert.deepEqual(result, { ok: false, error: "signing_failed" });
  });
}

test("s3: the post-sign check refuses the high-S twin of a valid signature, which the backend accepts", () => {
  const key = ecRawKey();
  const message = new TextEncoder().encode("strict post-sign check");
  const low = normalizeLowS(new Uint8Array(ecSign("SHA256", message, { key: key.privateKey, dsaEncoding: "ieee-p1363" })));
  const high = new Uint8Array(low);
  high.set(bigIntTo32(P256_ORDER - bytesToBigInt(low.subarray(32))), 32);
  const backend = createPublicKey({ key: { kty: "EC", crv: "P-256", x: key.jwk.x, y: key.jwk.y }, format: "jwk" });
  assert.equal(ecVerify("SHA256", message, { key: backend, dsaEncoding: "ieee-p1363" }, high), true, "the backend accepts the twin (malleability)");
  assert.equal(es256Verifies(message, low, key.publicKey), true);
  assert.equal(es256Verifies(message, high, key.publicKey), false, "the post-sign check is strict: high-S is refused");
});

test("s4: mutation: an identity normalizeLowS makes every high-S trial signing_failed (fails closed)", async () => {
  // A copy of src/ under the ignored node_modules/.cache, with normalizeLowS's body replaced by the
  // identity. The copy resolves the verifier from this repository's node_modules, exactly as src/ does.
  mkdirSync(join(REPO, "node_modules/.cache"), { recursive: true });
  const dir = mkdtempSync(join(REPO, "node_modules/.cache/bap-mutant-"));
  try {
    cpSync(join(REPO, "src"), join(dir, "src"), { recursive: true });
    // Module-scope lookup stops at node_modules, so the copy declares its own ESM scope.
    writeFileSync(join(dir, "package.json"), JSON.stringify({ type: "module" }));
    const file = join(dir, "src/es256.ts");
    const original = readFileSync(file, "utf8");
    const marker = "export function normalizeLowS(signature: Uint8Array): Uint8Array {";
    assert.ok(original.includes(marker), "the mutation site exists");
    writeFileSync(file, original.replace(marker, `${marker}\n  return signature; // MUTANT: identity normalization`));
    const mutant = (await import(pathToFileURL(join(dir, "src/index.ts")).href)) as typeof import("../src/index.js");

    const TRIALS = 64;
    let high = 0;
    for (let i = 0; i < TRIALS; i++) {
      const holder = ecRawKey();
      const grant = await fixtureGrant(holder);
      const raws: Uint8Array[] = [];
      const result = await mutant.signV3Report(report(grant), ecHandleFor(holder, { keyId: "holder-key", rawSignatures: raws }), { issuedAt: 1500, proofId: "urn:example:proof:s4" });
      const raw = raws[0];
      assert.ok(raw !== undefined, "the handle signed once");
      if (bytesToBigInt(raw.subarray(32)) > P256_HALF_ORDER) {
        high += 1;
        assert.deepEqual(result, { ok: false, error: "signing_failed" }, `trial ${i}: an unnormalized high-S signature must fail closed`);
      } else {
        assert.equal(result.ok, true, `trial ${i}: a naturally low-S signature still signs`);
      }
    }
    assert.ok(high > 0, "the sample contains at least one natural high-S signature (rate about 1/2)");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
