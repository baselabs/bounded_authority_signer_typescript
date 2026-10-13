// The weak-key gates (U11 of the strict-Ed25519 erratum). Two closures:
//   w1. handle construction refuses a weak public key at every Ed25519 entry
//       point (src/handle.ts → the verifier's acceptablePublicKey). The refusal
//       happens BEFORE sign() is called and returns the existing closed
//       invalid_key_handle. Removing the acceptance check reddens every leg.
//   w2. the post-sign self-verify is the verifier's verifyStrict, not
//       node:crypto's lenient verify (src/sign.ts). On a lenient backend the
//       signature R = identity, S = 0 verifies under the identity key; the
//       strict check refuses it. Reverting to node:crypto reddens this leg on
//       any runtime whose backend accepts that forgery (Node 22.x does).
// The ES256 (P-256) paths are unaffected and covered by v3.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { acceptablePublicKey } from "@bounded-authority-protocol/verifier";
import {
  signAnchor, signGrant, signKeyTransition, signLocalLoopbackReport, signReport,
} from "../src/index.js";
import { resolveIssuerIdentity, resolveKeyIdentity, resolvePublicKey, type KeyHandle, type KeyRole } from "../src/handle.js";
import { signatureVerifies } from "../src/sign.js";
import { amountArgs, handleFor, rawKey } from "./helpers.js";

const unhex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, "hex"));

// Literal vectors, independent of src/ and of the verifier's tables.
const WEAK_KEYS: readonly { name: string; key: Uint8Array }[] = [
  ["identity point (order 1)", "0100000000000000000000000000000000000000000000000000000000000000"],
  ["order 2", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
  ["order 4 (y = 0)", "0000000000000000000000000000000000000000000000000000000000000000"],
  ["order 4 (y = 0, sign bit set)", "0000000000000000000000000000000000000000000000000000000000000080"],
  ["order 8 (a)", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"],
  ["order 8 (b)", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"],
  ["order 8 (c)", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"],
  ["order 8 (d)", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"],
  ["y >= p alias of the identity (y = p + 1)", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
  ["y >= p alias of order 4 (y = p)", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
  ["identity with the sign bit set (x = 0)", "0100000000000000000000000000000000000000000000000000000000000080"],
  ["y >= p alias of an on-curve point (y = 3 + p)", "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
  ["not on the curve (y = 7)", "0700000000000000000000000000000000000000000000000000000000000000"],
].map(([name, hex]) => ({ name: name!, key: unhex(hex!) }));

// A handle that reports a caller-chosen public key and signs R = identity, S = 0
// (the forgery the cofactorless equation accepts under the identity key).
const FORGED = new Uint8Array(64);
FORGED[0] = 1;

interface WeakHandle { handle: KeyHandle; signCalls: { count: number } }

function weakHandle(publicKey: Uint8Array, role?: KeyRole): WeakHandle {
  const signCalls = { count: 0 };
  const handle: KeyHandle = {
    sign: () => { signCalls.count += 1; return FORGED; },
    publicKey: () => publicKey,
    thumbprint: () => "AA",
    keyIdentity: () => ({ keyId: "weak-key", publicKey }),
    ...(role === undefined ? {} : { signingIdentity: () => ({ role, keyId: "weak-key", publicKey }) }),
  };
  return { handle, signCalls };
}

async function realGrant(): Promise<Uint8Array> {
  const issuer = rawKey();
  const holder = rawKey();
  const g = await signGrant({
    issuer: "https://issuer.example.test", grantId: "urn:example:grant:wk",
    audiences: ["https://resource.example.test"],
    issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: holder.thumbprint,
    operations: [{ name: "transfer", selectors: [{ kind: "all" } as never] }],
  }, handleFor(issuer, { keyId: "issuer-key", role: "issuer" }));
  if (!g.ok) throw new Error("fixture grant signing failed");
  return g.value.grant;
}

const grantInput = {
  issuer: "https://issuer.example.test", grantId: "urn:example:grant:w1",
  audiences: ["https://resource.example.test"],
  issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint: rawKey().thumbprint, operations: [{ name: "transfer", selectors: [{ kind: "all" } as never] }],
};

test("w0: the weak-key vectors are all outside acceptablePublicKey, and a fresh key is inside it", () => {
  for (const { name, key } of WEAK_KEYS) assert.equal(acceptablePublicKey(key), false, name);
  assert.equal(acceptablePublicKey(rawKey().publicKey), true);
});

test("w1/resolvers: a weak public key resolves to undefined through every handle resolver", async () => {
  for (const { name, key } of WEAK_KEYS) {
    const { handle } = weakHandle(key, "issuer");
    assert.equal(await resolvePublicKey(handle), undefined, `resolvePublicKey: ${name}`);
    assert.equal(await resolveKeyIdentity(handle), undefined, `resolveKeyIdentity: ${name}`);
    assert.equal(await resolveIssuerIdentity(handle), undefined, `resolveIssuerIdentity: ${name}`);
  }
});

test("w1/resolvers: an acceptable key still resolves", async () => {
  const k = rawKey();
  const { handle } = weakHandle(k.publicKey, "issuer");
  assert.deepEqual(await resolvePublicKey(handle), k.publicKey);
  assert.deepEqual((await resolveKeyIdentity(handle))?.publicKey, k.publicKey);
  assert.deepEqual((await resolveIssuerIdentity(handle))?.publicKey, k.publicKey);
});

function assertRefused(r: { ok: boolean }, calls: { count: number }, label: string): void {
  assert.equal(r.ok, false, `${label}: must be refused`);
  assert.equal((r as unknown as { error: string }).error, "invalid_key_handle", label);
  assert.equal(calls.count, 0, `${label}: sign() must never be called for a weak key`);
}

test("w1/signReport: a weak holder key handle is invalid_key_handle and sign() is never called", async () => {
  const grantCompact = await realGrant();
  for (const { name, key } of WEAK_KEYS) {
    const { handle, signCalls } = weakHandle(key);
    const r = await signReport({
      grantCompact, operation: "transfer", method: "POST", targetUri: "https://resource.example.test/invoke",
      invocationId: "550e8400-e29b-41d4-a716-446655440000", castArguments: amountArgs(),
    }, handle, { issuedAt: 1500, proofId: "urn:example:proof:wk-1" });
    assertRefused(r, signCalls, `signReport / ${name}`);
  }
});

test("w1/signLocalLoopbackReport: a weak holder key handle is invalid_key_handle and sign() is never called", async () => {
  const grantCompact = await realGrant();
  for (const { name, key } of WEAK_KEYS) {
    const { handle, signCalls } = weakHandle(key);
    const r = await signLocalLoopbackReport({
      grantCompact, operation: "transfer", method: "POST", targetUri: "http://127.0.0.1:8080/invoke",
      invocationId: "550e8400-e29b-41d4-a716-446655440000", castArguments: amountArgs(), nonce: "challenge-7f3a",
    }, handle, { issuedAt: 1500, proofId: "urn:example:proof:wk-lb" });
    assertRefused(r, signCalls, `signLocalLoopbackReport / ${name}`);
  }
});

test("w1/signAnchor: a weak keyIdentity is invalid_key_handle and sign() is never called", async () => {
  for (const { name, key } of WEAK_KEYS) {
    const { handle, signCalls } = weakHandle(key);
    const r = await signAnchor(
      { anchorId: "urn:example:anchor:wk", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) },
      handle, { anchoredAt: 1200 },
    );
    assertRefused(r, signCalls, `signAnchor / ${name}`);
  }
});

test("w1/signGrant: a weak issuer identity is invalid_key_handle and sign() is never called", async () => {
  for (const { name, key } of WEAK_KEYS) {
    const { handle, signCalls } = weakHandle(key, "issuer");
    const r = await signGrant(grantInput, handle, {});
    assertRefused(r, signCalls, `signGrant / ${name}`);
  }
});

test("w1/signKeyTransition: a weak current-key identity is invalid_key_handle and sign() is never called", async () => {
  for (const { name, key } of WEAK_KEYS) {
    const { handle, signCalls } = weakHandle(key);
    const r = await signKeyTransition({
      transitionId: "urn:example:transition:wk", chainId: "urn:example:chain", effectiveAt: 1300,
      nextKeyId: "next-key", nextPublicKey: rawKey().publicKey,
    }, handle, {});
    assertRefused(r, signCalls, `signKeyTransition / ${name}`);
  }
});

test("w2: the self-verify refuses R = identity, S = 0 under the identity key (strict, not lenient)", () => {
  const identity = unhex("0100000000000000000000000000000000000000000000000000000000000000");
  assert.equal(signatureVerifies(new TextEncoder().encode("anything"), FORGED, identity), false);
});

test("w2: the self-verify refuses a signature whose key is any weak vector", () => {
  const message = new TextEncoder().encode("protected.payload");
  for (const { name, key } of WEAK_KEYS) {
    assert.equal(signatureVerifies(message, FORGED, key), false, name);
  }
});
