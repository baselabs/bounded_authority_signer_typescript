// The oracle: every compact this signer produces is verified through the
// INDEPENDENT verifier package before this library claims anything (no
// self-round-trip evidence). Issuer signs a grant → holder signs a report over
// it → the verifier's checkEnvelope consumes both; the anchor and transition
// signers verify through their historical surfaces.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  checkEnvelope,
  publicKeyThumbprintRaw,
  checkLocalLoopbackHttpEnvelope,
  verifyGrant,
  verifyHistoricalAnchor,
  verifyKeyTransition,
} from "@bounded-authority-protocol/verifier";
import { signAnchor, signGrant, signKeyTransition, signLocalLoopbackReport, signReport } from "../src/index.js";
import { amountArgs, b64, handleFor, rawKey } from "./helpers.js";

test("oracle: issuer grant → holder report → verifier checkEnvelope consumes both", async () => {
  const issuer = rawKey();
  const holder = rawKey();

  const grant = await signGrant(
    {
      issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
      audiences: ["https://resource.example.test"],
      issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
      holderThumbprint: holder.thumbprint,
      operations: [{ name: "transfer", selectors: [{ kind: "all" } as never] }],
    },
    handleFor(issuer, { keyId: "issuer-key", role: "issuer" }),
  );
  assert.equal(grant.ok, true, `grant signing failed: ${JSON.stringify(grant)}`);

  // The grant verifies standalone through the independent verifier.
  const verified = verifyGrant(grant.value.grant, { keyId: "issuer-key", publicKey: issuer.publicKey }, {
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    evaluationTime: 1500, clockSkew: 60,
  });
  assert.equal(verified.ok, true, "the signed grant must verify through the verifier package");

  const envelope = await signReport(
    {
      grantCompact: grant.value.grant, operation: "transfer", method: "POST",
      targetUri: "https://resource.example.test/invoke", invocationId: "550e8400-e29b-41d4-a716-446655440000",
      castArguments: amountArgs(),
    },
    handleFor(holder, { keyId: "holder-key" }),
    { issuedAt: 1500, proofId: "urn:example:proof:1" },
  );
  assert.equal(envelope.ok, true, `report signing failed: ${JSON.stringify(envelope)}`);
  assert.deepEqual(envelope.value.grant, grant.value.grant, "the grant passes through untouched");

  const at = checkEnvelope(envelope.value.grant, envelope.value.proof, {
    trustedIssuer: { keyId: "issuer-key", publicKey: issuer.publicKey },
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    method: "POST", targetUri: "https://resource.example.test/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "transfer",
    castArguments: amountArgs(), evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300,
    nonce: { kind: "not_required" },
  });
  assert.equal(at.ok, true, `the envelope must verify through checkEnvelope: ${JSON.stringify(at)}`);
});

test("oracle: local-loopback proof verifies through the profile's checkEnvelope", async () => {
  const issuer = rawKey();
  const holder = rawKey();
  const grant = await signGrant(
    {
      issuer: "https://issuer.example.test", grantId: "urn:example:grant:lb-1",
      audiences: ["https://resource.example.test"],
      issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
      holderThumbprint: holder.thumbprint,
      operations: [{ name: "transfer", selectors: [{ kind: "all" } as never] }],
    },
    handleFor(issuer, { keyId: "issuer-key", role: "issuer" }),
  );
  assert.equal(grant.ok, true);

  const envelope = await signLocalLoopbackReport(
    {
      grantCompact: grant.value.grant, operation: "transfer", method: "POST",
      targetUri: "http://127.0.0.1:8080/invoke", invocationId: "550e8400-e29b-41d4-a716-446655440000",
      castArguments: amountArgs(), nonce: "challenge-7f3a",
    },
    handleFor(holder, { keyId: "holder-key" }),
    { issuedAt: 1500, proofId: "urn:example:proof:lb-1" },
  );
  assert.equal(envelope.ok, true, `loopback signing failed: ${JSON.stringify(envelope)}`);

  const at = checkLocalLoopbackHttpEnvelope(envelope.value.grant, envelope.value.proof, {
    trustedIssuer: { keyId: "issuer-key", publicKey: issuer.publicKey },
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    method: "POST", targetUri: "http://127.0.0.1:8080/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "transfer",
    castArguments: amountArgs(), evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300,
    nonce: { kind: "required", value: "challenge-7f3a" },
  });
  assert.equal(at.ok, true, `the loopback envelope must verify through the profile verifier: ${JSON.stringify(at)}`);
});

test("oracle: anchor and key-transition compacts verify through the historical surfaces", async () => {
  const signer = rawKey();
  const successor = rawKey();
  const chainHash = new Uint8Array(32); // genesis all-zero chain hash

  const anchor = await signAnchor(
    { anchorId: "urn:example:anchor:start", chainId: "urn:example:chain", sequence: 0, chainHash },
    handleFor(signer, { keyId: "chain-key" }),
    { anchoredAt: 1200 },
  );
  assert.equal(anchor.ok, true, `anchor signing failed: ${JSON.stringify(anchor)}`);

  const anchorOk = verifyHistoricalAnchor(anchor.value.anchor, {
    keyId: "chain-key", publicKey: signer.publicKey, validFrom: 0, validBefore: null,
  }, {
    anchorId: "urn:example:anchor:start", chainId: "urn:example:chain", keyId: "chain-key",
    sequence: 0, anchoredAt: 1200, chainHash,
    keyFingerprint: publicKeyThumbprintRaw(signer.publicKey),
  });
  assert.equal(anchorOk.ok, true, `the anchor must verify: ${JSON.stringify(anchorOk)}`);

  const transition = await signKeyTransition(
    {
      transitionId: "urn:example:transition:1", chainId: "urn:example:chain", effectiveAt: 1500,
      nextKeyId: "chain-key-2", nextPublicKey: successor.publicKey,
    },
    handleFor(signer, { keyId: "chain-key" }),
  );
  assert.equal(transition.ok, true, `transition signing failed: ${JSON.stringify(transition)}`);

  const trOk = verifyKeyTransition(transition.value.keyTransition,
    { keyId: "chain-key", publicKey: signer.publicKey, validFrom: 0, validBefore: null },
    { keyId: "chain-key-2", publicKey: successor.publicKey, validFrom: 1500, validBefore: null },
    {
      transitionId: "urn:example:transition:1", chainId: "urn:example:chain", effectiveAt: 1500,
      currentKeyFingerprint: publicKeyThumbprintRaw(signer.publicKey),
      nextKeyFingerprint: publicKeyThumbprintRaw(successor.publicKey),
      currentKeyId: "chain-key", nextKeyId: "chain-key-2",
    });
  assert.equal(trOk.ok, true, `the transition must verify: ${JSON.stringify(trOk)}`);
});
