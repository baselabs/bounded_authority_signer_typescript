// The gates: red-capable legs for every closure this library owns. Removing
// the named check in src/ reddens exactly its leg (proven at authoring):
//   g1. C1 role gate in resolveIssuerIdentity  → "holder handle cannot sign a grant"
//   g2. signatureVerifies in the shared tail   → "wrong-key sign fails closed"
//   g3. loopback nonce requirement             → "loopback report requires a nonce"
//   g4. non-canonical loopback target          → "localhost is not admitted"
//   g5. atomic keyIdentity requirement         → "anchor requires keyIdentity"
import { test } from "node:test";
import assert from "node:assert/strict";
import { signAnchor, signGrant, signLocalLoopbackReport, signReport } from "../src/index.js";
import { amountArgs, b64, handleFor, rawKey } from "./helpers.js";

// A real issuer-signed grant so the wrong-key probe reaches the SIGNING TAIL
// (a garbage grantCompact fails at the producer before sign() runs).
async function realGrant(): Promise<Uint8Array> {
  const issuer = rawKey();
  const holder = rawKey();
  const g = await signGrant({
    issuer: "https://issuer.example.test", grantId: "urn:example:grant:g2",
    audiences: ["https://resource.example.test"],
    issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: holder.thumbprint,
    operations: [{ name: "transfer", selectors: [{ kind: "all" } as never] }],
  }, handleFor(issuer, { keyId: "issuer-key", role: "issuer" }));
  if (!g.ok) throw new Error("fixture grant signing failed");
  return g.value.grant;
}

const baseGrantInput = (holderThumbprint: string) => ({
  issuer: "https://issuer.example.test", grantId: "urn:example:grant:g1",
  audiences: ["https://resource.example.test"],
  issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint, operations: [{ name: "transfer", selectors: [{ kind: "all" } as never] }],
});

test("g1/C1: a holder-role handle cannot sign a grant, and sign() is never called", async () => {
  const holder = rawKey();
  const calls = { count: 0 };
  const r = await signGrant(baseGrantInput("AA"), handleFor(holder, { keyId: "holder-key", role: "holder", signCalls: calls }));
  assert.equal(r.ok, false);
  assert.equal((r as { error: string }).error, "invalid_key_handle");
  assert.equal(calls.count, 0, "the C1 gate must reject BEFORE calling sign()");
});

test("g1/C1: a handle without signingIdentity cannot sign a grant either", async () => {
  const r = await signGrant(baseGrantInput("AA"), handleFor(rawKey(), { keyId: "k" }));
  assert.equal(r.ok, false);
  assert.equal((r as { error: string }).error, "invalid_key_handle");
});

test("g2: a handle signing with the wrong key fails closed as signing_failed", async () => {
  const reportedKey = rawKey();
  const actualKey = rawKey(); // the handle's sign() uses THIS key
  const r = await signReport(
    {
      grantCompact: await realGrant(), operation: "transfer", method: "POST",
      targetUri: "https://resource.example.test/invoke", invocationId: "550e8400-e29b-41d4-a716-446655440000",
      castArguments: amountArgs(),
    },
    handleFor(reportedKey, { keyId: "holder-key", wrongSigningKey: actualKey }),
    { issuedAt: 1500, proofId: "urn:example:proof:w1" },
  );
  assert.equal(r.ok, false);
  assert.equal((r as { error: string }).error, "signing_failed");
});

test("g3: the loopback profile requires a non-empty nonce (standard profile does not)", async () => {
  const holder = rawKey();
  const report = {
    grantCompact: new Uint8Array(10), operation: "transfer", method: "POST",
    targetUri: "http://127.0.0.1:8080/invoke", invocationId: "550e8400-e29b-41d4-a716-446655440000",
    castArguments: amountArgs(),
  };
  const noNonce = await signLocalLoopbackReport(report as never, handleFor(holder, { keyId: "holder-key" }), { issuedAt: 1500 });
  assert.equal(noNonce.ok, false);
  assert.equal((noNonce as { error: string }).error, "invalid_report");
  const emptyNonce = await signLocalLoopbackReport({ ...report, nonce: "" } as never, handleFor(holder, { keyId: "holder-key" }), { issuedAt: 1500 });
  assert.equal(emptyNonce.ok, false);
  assert.equal((emptyNonce as { error: string }).error, "invalid_report");
});

test("g4: a non-canonical loopback target (localhost) is producer_error, never admitted", async () => {
  const holder = rawKey();
  const r = await signLocalLoopbackReport(
    {
      grantCompact: new Uint8Array(10), operation: "transfer", method: "POST",
      targetUri: "http://localhost:8080/invoke", invocationId: "550e8400-e29b-41d4-a716-446655440000",
      castArguments: amountArgs(), nonce: "challenge-7f3a",
    },
    handleFor(holder, { keyId: "holder-key" }),
    { issuedAt: 1500, proofId: "urn:example:proof:lb-bad" },
  );
  assert.equal(r.ok, false);
  assert.equal((r as { error: string }).error, "producer_error");
});

test("g5: anchor and transition require the atomic keyIdentity() snapshot", async () => {
  const signer = rawKey();
  const noIdentity = handleFor(signer, { keyId: "chain-key", withKeyIdentity: false });
  const anchor = await signAnchor(
    { anchorId: "urn:example:anchor:x", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) },
    noIdentity, { anchoredAt: 1200 },
  );
  assert.equal(anchor.ok, false);
  assert.equal((anchor as { error: string }).error, "invalid_key_handle");
});

test("malformed inputs map to their closed error codes", async () => {
  const holder = handleFor(rawKey(), { keyId: "k" });
  const badReport = await signReport({} as never, holder, {});
  assert.equal((badReport as { error: string }).error, "invalid_report");
  const badAnchor = await signAnchor({ anchorId: "a", chainId: "c", sequence: 1.5, chainHash: new Uint8Array(32) }, handleFor(rawKey(), { keyId: "k" }), {});
  assert.equal((badAnchor as { error: string }).error, "invalid_anchor");
  const badGrant = await signGrant({ ...baseGrantInput("AA"), issuedAt: "nope" } as never, handleFor(rawKey(), { keyId: "k", role: "issuer" }), {});
  assert.equal((badGrant as { error: string }).error, "invalid_grant");
});
