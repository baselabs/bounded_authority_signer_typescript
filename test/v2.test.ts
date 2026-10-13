// The contract-major-2 signers (signV2Grant, signV2Report, signV2Anchor, signV2KeyTransition): the
// existing Ed25519 caller-owned KeyHandle over the verifier package's public v2 signing inputs and
// v2.assembleCompact. Every compact is verified through the verifier package's v2 namespace (no
// self-round-trip evidence), each major refuses the other's envelope, and the closure gates the v1
// surface owns (C1 role gate, wrong-key guard, atomic identity, weak-key refusal, closed errors) hold
// on the v2 surface too.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkEnvelope, publicKeyThumbprintRaw, v2 } from "@bounded-authority-protocol/verifier";
import {
  signGrant,
  signReport,
  signV2Anchor,
  signV2Grant,
  signV2KeyTransition,
  signV2Report,
  type V2SignerEvent,
} from "../src/index.js";
import { amountArgs, handleFor, rawKey, type RawKey } from "./helpers.js";

const ISSUER = "https://issuer.example.test";
const AUDIENCE = "https://resource.example.test";
const TARGET = `${AUDIENCE}/invoke`;
const INVOCATION_ID = "550e8400-e29b-41d4-a716-446655440000";

const lteGrant = (holderThumbprint: string, limit = 10_000) => ({
  issuer: ISSUER, grantId: "urn:example:grant:v2-1", audiences: [AUDIENCE],
  issuedAt: 1000, notBefore: 1000, expiresAt: 2000, holderThumbprint,
  operations: [{ name: "transfer", selectors: [{ kind: "lte" as const, path: ["amount"], value: { t: "int" as const, v: limit } }] }],
});

const report = (grantCompact: Uint8Array) => ({
  grantCompact, operation: "transfer", method: "POST", targetUri: TARGET,
  invocationId: INVOCATION_ID, castArguments: amountArgs(),
});

const expected = (issuer: RawKey) => ({
  trustedIssuer: { keyId: "issuer-key", publicKey: issuer.publicKey },
  issuer: ISSUER, audience: AUDIENCE, method: "POST", targetUri: TARGET,
  invocationId: INVOCATION_ID, operation: "transfer", castArguments: amountArgs(),
  evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" as const },
});

async function v2Envelope(issuer: RawKey, holder: RawKey) {
  const grant = await signV2Grant(lteGrant(holder.thumbprint), handleFor(issuer, { keyId: "issuer-key", role: "issuer" }));
  assert.equal(grant.ok, true, `v2 grant signing failed: ${JSON.stringify(grant)}`);
  if (!grant.ok) throw new Error("unreachable");
  const envelope = await signV2Report(report(grant.value.grant), handleFor(holder, { keyId: "holder-key" }), { issuedAt: 1500, proofId: "urn:example:proof:v2-1" });
  assert.equal(envelope.ok, true, `v2 report signing failed: ${JSON.stringify(envelope)}`);
  if (!envelope.ok) throw new Error("unreachable");
  return { grant: grant.value.grant, envelope: envelope.value };
}

test("v2 oracle: issuer grant (lte selector) -> holder report -> v2.verifyGrant and v2.checkEnvelope accept both", async () => {
  const issuer = rawKey();
  const holder = rawKey();
  const { grant, envelope } = await v2Envelope(issuer, holder);
  assert.deepEqual(envelope.grant, grant, "the grant passes through untouched");

  const g = v2.verifyGrant(grant, { keyId: "issuer-key", publicKey: issuer.publicKey }, { issuer: ISSUER, audience: AUDIENCE, evaluationTime: 1500, clockSkew: 60 });
  assert.equal(g.ok, true, `the v2 grant must verify: ${JSON.stringify(g)}`);
  const at = v2.checkEnvelope(envelope.grant, envelope.proof, expected(issuer));
  assert.equal(at.ok, true, `the v2 envelope must verify through v2.checkEnvelope: ${JSON.stringify(at)}`);
});

test("v2 oracle: the lte bound is in the signed grant (an amount above it is refused by v2.checkEnvelope)", async () => {
  const issuer = rawKey();
  const holder = rawKey();
  const grant = await signV2Grant(lteGrant(holder.thumbprint, 4_999), handleFor(issuer, { keyId: "issuer-key", role: "issuer" }));
  assert.equal(grant.ok, true);
  if (!grant.ok) return;
  const envelope = await signV2Report(report(grant.value.grant), handleFor(holder, { keyId: "holder-key" }), { issuedAt: 1500, proofId: "urn:example:proof:v2-2" });
  assert.equal(envelope.ok, true);
  if (!envelope.ok) return;
  assert.equal(v2.checkEnvelope(envelope.value.grant, envelope.value.proof, expected(issuer)).ok, false, "5000 is above the signed bound 4999");
});

test("v2 oracle: the majors refuse each other's envelopes (v1 checkEnvelope refuses v2, v2.checkEnvelope refuses v1)", async () => {
  const issuer = rawKey();
  const holder = rawKey();
  const { envelope } = await v2Envelope(issuer, holder);
  assert.equal(checkEnvelope(envelope.grant, envelope.proof, expected(issuer)).ok, false, "v1 refuses v2 bytes");

  const v1Grant = await signGrant({ ...lteGrant(holder.thumbprint), operations: [{ name: "transfer", selectors: [{ kind: "all" } as never] }] },
    handleFor(issuer, { keyId: "issuer-key", role: "issuer" }));
  assert.equal(v1Grant.ok, true);
  if (!v1Grant.ok) return;
  const v1 = await signReport(report(v1Grant.value.grant), handleFor(holder, { keyId: "holder-key" }), { issuedAt: 1500, proofId: "urn:example:proof:v1" });
  assert.equal(v1.ok, true);
  if (!v1.ok) return;
  assert.equal(checkEnvelope(v1.value.grant, v1.value.proof, expected(issuer)).ok, true, "control: v1 accepts v1 bytes");
  assert.equal(v2.checkEnvelope(v1.value.grant, v1.value.proof, expected(issuer)).ok, false, "v2 refuses v1 bytes");
});

test("v2 oracle: anchor and key-transition compacts verify through the v2 historical surfaces", async () => {
  const signer = rawKey();
  const successor = rawKey();
  const chainHash = new Uint8Array(32);
  const anchor = await signV2Anchor(
    { anchorId: "urn:example:anchor:v2-start", chainId: "urn:example:chain", sequence: 0, chainHash },
    handleFor(signer, { keyId: "chain-key" }), { anchoredAt: 1200 },
  );
  assert.equal(anchor.ok, true, `v2 anchor signing failed: ${JSON.stringify(anchor)}`);
  if (!anchor.ok) return;
  const anchorOk = v2.verifyHistoricalAnchor(anchor.value.anchor, { keyId: "chain-key", publicKey: signer.publicKey, validFrom: 0, validBefore: null }, {
    anchorId: "urn:example:anchor:v2-start", chainId: "urn:example:chain", keyId: "chain-key",
    sequence: 0, anchoredAt: 1200, chainHash, keyFingerprint: publicKeyThumbprintRaw(signer.publicKey),
  });
  assert.equal(anchorOk.ok, true, `the v2 anchor must verify: ${JSON.stringify(anchorOk)}`);

  const transition = await signV2KeyTransition(
    { transitionId: "urn:example:transition:v2-1", chainId: "urn:example:chain", effectiveAt: 1500, nextKeyId: "chain-key-2", nextPublicKey: successor.publicKey },
    handleFor(signer, { keyId: "chain-key" }),
  );
  assert.equal(transition.ok, true, `v2 transition signing failed: ${JSON.stringify(transition)}`);
  if (!transition.ok) return;
  const trOk = v2.verifyKeyTransition(transition.value.keyTransition,
    { keyId: "chain-key", publicKey: signer.publicKey, validFrom: 0, validBefore: null },
    { keyId: "chain-key-2", publicKey: successor.publicKey, validFrom: 1500, validBefore: null },
    {
      transitionId: "urn:example:transition:v2-1", chainId: "urn:example:chain", effectiveAt: 1500,
      currentKeyFingerprint: publicKeyThumbprintRaw(signer.publicKey), nextKeyFingerprint: publicKeyThumbprintRaw(successor.publicKey),
      currentKeyId: "chain-key", nextKeyId: "chain-key-2",
    });
  assert.equal(trOk.ok, true, `the v2 transition must verify: ${JSON.stringify(trOk)}`);
});

test("v2 gates: C1, a holder-role handle (or one without signingIdentity) cannot sign a grant, and sign() is never called", async () => {
  const calls = { count: 0 };
  const holder = rawKey();
  const r = await signV2Grant(lteGrant("AA"), handleFor(holder, { keyId: "holder-key", role: "holder", signCalls: calls }));
  assert.deepEqual(r, { ok: false, error: "invalid_key_handle" });
  assert.equal(calls.count, 0);
  assert.deepEqual(await signV2Grant(lteGrant("AA"), handleFor(rawKey(), { keyId: "k" })), { ok: false, error: "invalid_key_handle" });
});

test("v2 gates: a handle signing with the wrong key fails closed as signing_failed", async () => {
  const issuer = rawKey();
  const holder = rawKey();
  const grant = await signV2Grant(lteGrant(holder.thumbprint), handleFor(issuer, { keyId: "issuer-key", role: "issuer" }));
  assert.equal(grant.ok, true);
  if (!grant.ok) return;
  const r = await signV2Report(report(grant.value.grant), handleFor(holder, { keyId: "holder-key", wrongSigningKey: rawKey() }), { issuedAt: 1500, proofId: "urn:example:proof:w" });
  assert.deepEqual(r, { ok: false, error: "signing_failed" });
});

test("v2 gates: anchor and transition require the atomic keyIdentity() snapshot", async () => {
  const noIdentity = handleFor(rawKey(), { keyId: "chain-key", withKeyIdentity: false });
  assert.deepEqual(await signV2Anchor({ anchorId: "urn:example:anchor:x", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) }, noIdentity, { anchoredAt: 1200 }),
    { ok: false, error: "invalid_key_handle" });
  assert.deepEqual(await signV2KeyTransition({ transitionId: "urn:example:t", chainId: "urn:example:chain", effectiveAt: 1, nextKeyId: "n", nextPublicKey: rawKey().publicKey }, noIdentity),
    { ok: false, error: "invalid_key_handle" });
});

test("v2 gates: a weak (small-order) holder key is invalid_key_handle and sign() is never called", async () => {
  const calls = { count: 0 };
  const identity = new Uint8Array(32);
  identity[0] = 1; // the identity point, small order
  const r = await signV2Report(report(new Uint8Array(10)), {
    sign: () => { calls.count += 1; return new Uint8Array(64); }, publicKey: () => identity, thumbprint: () => "AA",
  }, { issuedAt: 1500, proofId: "urn:example:proof:weak" });
  assert.deepEqual(r, { ok: false, error: "invalid_key_handle" });
  assert.equal(calls.count, 0);
});

test("v2 gates: malformed inputs map to their closed error codes; a producer refusal is producer_error", async () => {
  const k = () => handleFor(rawKey(), { keyId: "k", role: "issuer" });
  assert.deepEqual(await signV2Report({} as never, k()), { ok: false, error: "invalid_report" });
  assert.deepEqual(await signV2Anchor({ anchorId: "a", chainId: "c", sequence: 1.5, chainHash: new Uint8Array(32) }, k()), { ok: false, error: "invalid_anchor" });
  assert.deepEqual(await signV2Grant({ ...lteGrant("AA"), issuedAt: "x" } as never, k()), { ok: false, error: "invalid_grant" });
  assert.deepEqual(await signV2KeyTransition({ transitionId: "t", chainId: "c", effectiveAt: 1, nextKeyId: "n", nextPublicKey: new Uint8Array(31) }, k()), { ok: false, error: "invalid_transition" });
  // A float lte bound is admitted by v2, a string bound is not: the producer refuses, closed.
  const bad = { ...lteGrant("AA"), operations: [{ name: "transfer", selectors: [{ kind: "lte" as const, path: ["amount"], value: { t: "string" as const, v: new TextEncoder().encode("x") } }] }] };
  assert.deepEqual(await signV2Grant(bad, k()), { ok: false, error: "producer_error" });
});

test("v2 events: start then stop on success, start then error on failure, with the v2 kinds", async () => {
  const issuer = rawKey();
  const holder = rawKey();
  const events: V2SignerEvent[] = [];
  const grant = await signV2Grant(lteGrant(holder.thumbprint), handleFor(issuer, { keyId: "issuer-key", role: "issuer" }), { onEvent: (e) => events.push(e) });
  assert.equal(grant.ok, true);
  await signV2Report({} as never, handleFor(holder, { keyId: "h" }), { onEvent: (e) => events.push(e) });
  assert.deepEqual(events, [
    { kind: "v2_grant", phase: "start" }, { kind: "v2_grant", phase: "stop" },
    { kind: "v2_report", phase: "start" }, { kind: "v2_report", phase: "error" },
  ]);
});
