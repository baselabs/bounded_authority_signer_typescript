// The v3 (BAP3-ES256-SHA256) battery: producer composition at the byte level,
// the low-S normalization (unit + property), and the four ES256 signers'
// closure gates. The no-self-round-trip ORACLE for the produced compacts runs
// in oracle.test.ts through the verifier package's v3 namespace (its 0.3.0
// release); the byte-level signature pinning here — each compact verified over
// the exact RFC 7515 signing input under node:crypto twice, in the raw
// ieee-p1363 (r||s) form and re-encoded as DER — stays as composition
// evidence under the oracle, not in place of it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey, sign as ecSign, verify as ecVerify } from "node:crypto";
import { strUtf8 } from "@bounded-authority-protocol/verifier";
import { P256_HALF_ORDER, P256_ORDER, es256Verifies, normalizeLowS } from "../src/es256.js";
import {
  V3_REQUEST_PREFIX,
  boundaryAnchorSigningInput,
  ecJwkFromRawPublicKey,
  ecThumbprint,
  grantSigningInput,
  isOnCurveP256,
  keyTransitionSigningInput,
  proofSigningInput,
} from "../src/v3.js";
import { signV3Anchor, signV3Grant, signV3KeyTransition, signV3Report } from "../src/index.js";
import { amountArgs, b64, ecHandleFor, ecRawKey, type EcRawKey } from "./helpers.js";

const P256_N = P256_ORDER;
const HALF = P256_HALF_ORDER;

// bigint view of a big-endian byte half.
const bytesToBigInt = (bytes: Uint8Array): bigint => BigInt("0x" + Buffer.from(bytes).toString("hex"));
const bigIntTo32 = (v: bigint): Uint8Array =>
  new Uint8Array(Buffer.from(v.toString(16).padStart(64, "0"), "hex"));

// DER ECDSA-Sig-Value from the raw (r, s) pair — the independent re-encoding
// every emitted signature must verify under.
function derFromRaw(raw: Uint8Array): Uint8Array {
  const int = (v: bigint): Buffer => {
    let hex = v.toString(16);
    if (hex.length % 2 === 1) hex = "0" + hex;
    let bytes = Buffer.from(hex, "hex");
    if (((bytes[0] ?? 0) & 0x80) !== 0) bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
    return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
  };
  const body = Buffer.concat([int(bytesToBigInt(raw.subarray(0, 32))), int(bytesToBigInt(raw.subarray(32)))]);
  return new Uint8Array(Buffer.concat([Buffer.from([0x30, body.length]), body]));
}

const sha256Of = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};

// A signing-input segment is ASCII base64url TEXT: read the text, then decode.
const segText = (segment: Uint8Array): string => Buffer.from(segment).toString("utf8");
const segJson = (segment: Uint8Array): unknown =>
  JSON.parse(Buffer.from(segText(segment), "base64url").toString("utf8"));

// Split a compact into its three ASCII segments.
const segments = (compact: Uint8Array): [string, string, string] => {
  const parts = Buffer.from(compact).toString("utf8").split(".");
  assert.equal(parts.length, 3, "a compact is three dot-separated segments");
  return [parts[0] ?? "", parts[1] ?? "", parts[2] ?? ""];
};
const decodeSegment = (seg: string): unknown => JSON.parse(Buffer.from(seg, "base64url").toString("utf8"));
const decodeBytes = (seg: string): Uint8Array => new Uint8Array(Buffer.from(seg, "base64url"));
const ecPublic = (key: { jwk: { x: string; y: string } }) =>
  createPublicKey({ key: { kty: "EC", crv: "P-256", x: key.jwk.x, y: key.jwk.y }, format: "jwk" });

const ISSUER = "https://issuer.example.test";
const AUDIENCE = "https://resource.example.test";
const GRANT_ID = "urn:example:grant:1";
const INVOCATION_ID = "550e8400-e29b-41d4-a716-446655440000";

const grantFixture = (holderThumbprint: string) => ({
  issuer: ISSUER, grantId: GRANT_ID, audiences: [AUDIENCE],
  issuedAt: 1000, notBefore: 1000, expiresAt: 2000, holderThumbprint,
  operations: [{ name: "transfer", selectors: [{ kind: "all" }] as never }],
});

// ---------------------------------------------------------------------------
// Producers — byte-level composition.

test("v3 producer: the raw EC fixture key is 65 bytes starting 0x04, and the JWK is exactly {crv, kty, x, y}", () => {
  const key = ecRawKey();
  assert.equal(key.publicKey.length, 65);
  assert.equal(key.publicKey[0], 0x04);
  assert.equal(Buffer.from(key.publicKey.subarray(1, 33)).toString("base64url"), key.jwk.x);
  assert.equal(Buffer.from(key.publicKey.subarray(33)).toString("base64url"), key.jwk.y);
  const jwk = ecJwkFromRawPublicKey(key.publicKey);
  assert.deepEqual(jwk, { crv: "P-256", kty: "EC", x: key.jwk.x, y: key.jwk.y });
  // RFC 7638: the library's JCS-built thumbprint equals the independently
  // hashed literal preimage (two spellings of one identity).
  assert.equal(ecThumbprint(key.publicKey), key.thumbprint);
});

test("v3 producer: grant signing input — ES256 header, v:3 payload, typed selectors, cnf.jkt passthrough", () => {
  const holder = ecRawKey();
  const produced = grantSigningInput({
    keyId: "issuer-key", ...grantFixture(holder.thumbprint),
    operations: [{
      name: "transfer",
      selectors: [
        { kind: "all" },
        { kind: "equals", path: ["amount"], value: { t: "int", v: 5000 } },
        { kind: "one_of", path: ["ccy"], values: [{ t: "string", v: strUtf8("USD") }] },
        { kind: "lte", path: ["amount"], value: { t: "int", v: 10000 } },
        { kind: "gte", path: ["amount"], value: { t: "float", v: 0.5 } },
      ],
    }],
  });
  assert.equal(produced.ok, true);

  // BYTE-LEVEL: the protected header is exactly the JCS form — member set AND order.
  assert.equal(
    Buffer.from(segText(produced.value.protectedSegment), "base64url").toString("utf8"),
    `{"alg":"ES256","kid":"issuer-key","typ":"ba+cap"}`,
  );

  const payload = segJson(produced.value.payloadSegment) as Record<string, unknown>;
  // JCS member order, pinned as the exact key sequence.
  assert.deepEqual(Object.keys(payload), ["aud", "cnf", "exp", "iat", "iss", "jti", "nbf", "operations", "v"]);
  assert.equal(payload.v, 3, "the v claim is exactly integer 3 (cross-major pin)");
  assert.equal((payload.cnf as { jkt: string }).jkt, holder.thumbprint, "cnf.jkt is the RFC 7638 EC thumbprint of the holder key");
  const sels = ((payload.operations as Array<{ selectors: Array<Record<string, unknown>> }>)[0]?.selectors) ?? [];
  // Selector values ride the grant payload as the RAW tagged JSON (the typed
  // ["integer", 5000] projection is the request-digest spelling, not the
  // selector spelling).
  assert.deepEqual(sels[0], { kind: "all" });
  assert.deepEqual(sels[1], { kind: "equals", path: ["amount"], value: 5000 });
  assert.deepEqual(sels[2], { kind: "one_of", path: ["ccy"], values: ["USD"] });
  assert.deepEqual(sels[3], { kind: "lte", path: ["amount"], value: 10000 });
  assert.deepEqual(sels[4], { kind: "gte", path: ["amount"], value: 0.5 });
});

test("v3 producer: proof signing input — byte-level header, BAP3 digest, ath, member order", () => {
  const holder = ecRawKey();
  const grantCompact = new TextEncoder().encode("aaa.bbb.ccc"); // scan-passable shape
  const produced = proofSigningInput({
    holderPublicKey: holder.publicKey,
    proofId: "urn:example:proof:1",
    method: "POST",
    targetUri: `${AUDIENCE}/invoke`,
    issuedAt: 1500,
    invocationId: INVOCATION_ID,
    operation: "transfer",
    grantCompact,
    castArguments: amountArgs(),
  });
  assert.equal(produced.ok, true);

  // BYTE-LEVEL: member set AND order of the proof header — alg, jwk{crv,kty,x,y}, typ.
  assert.equal(
    Buffer.from(segText(produced.value.protectedSegment), "base64url").toString("utf8"),
    `{"alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":"${holder.jwk.x}","y":"${holder.jwk.y}"},"typ":"dpop+jwt"}`,
  );

  const payload = segJson(produced.value.payloadSegment) as Record<string, string> & { v: number };
  assert.deepEqual(Object.keys(payload), ["ath", "ba_inv", "ba_op", "ba_req", "htm", "htu", "iat", "jti", "v"]);
  assert.equal(payload.v, 3, "the v claim is exactly integer 3 (cross-major pin)");
  // ath: SHA-256 of the exact grant compact bytes, unpadded base64url.
  assert.equal(payload.ath, b64(sha256Of(grantCompact)));
  // ba_req: SHA-256("BAP3-REQUEST\0" || JCS([operation, typed(args)])) — the
  // JCS expectation here is the HAND-DERIVED literal for the fixture args,
  // not a library call.
  const handDerivedJcs = `["transfer",["object",{"amount":["integer",5000]}]]`;
  assert.equal(
    payload.ba_req,
    b64(sha256Of(new TextEncoder().encode("BAP3-REQUEST\0"), new TextEncoder().encode(handDerivedJcs))),
  );
  // The domain separator itself is the exact 13 ASCII bytes ending in NUL.
  assert.deepEqual(V3_REQUEST_PREFIX, new Uint8Array([0x42, 0x41, 0x50, 0x33, 0x2d, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x00]));
  assert.equal(Buffer.from(V3_REQUEST_PREFIX).toString("utf8"), "BAP3-REQUEST\0");
  // The digest is NOT the v1 digest (the prefix is load-bearing).
  assert.notEqual(payload.ba_req, b64(sha256Of(new TextEncoder().encode("BAP1-REQUEST\0"), new TextEncoder().encode(handDerivedJcs))));
});

test("v3 producer: anchor and transition signing inputs — fingerprints, v:3, closed rejections", () => {
  const signer = ecRawKey();
  const successor = ecRawKey();
  const chainHash = new Uint8Array(32); // genesis all-zero

  const anchor = boundaryAnchorSigningInput({
    anchorId: "urn:example:anchor:start", anchoredAt: 1200, chainId: "urn:example:chain",
    sequence: 0, chainHash, keyId: "chain-key", publicKey: signer.publicKey,
  });
  assert.equal(anchor.ok, true);
  assert.equal(
    Buffer.from(segText(anchor.value.protectedSegment), "base64url").toString("utf8"),
    `{"alg":"ES256","kid":"chain-key","typ":"ba+chain-anchor"}`,
  );
  const anchorPayload = segJson(anchor.value.payloadSegment) as Record<string, unknown>;
  assert.deepEqual(Object.keys(anchorPayload), ["anchor_id", "anchored_at", "chain_hash", "chain_id", "key_fingerprint", "sequence", "v"]);
  assert.equal(anchorPayload.v, 3);
  assert.equal(anchorPayload.key_fingerprint, signer.thumbprint, "the anchor fingerprint is the RFC 7638 EC thumbprint");

  const transition = keyTransitionSigningInput({
    transitionId: "urn:example:transition:1", chainId: "urn:example:chain", effectiveAt: 1500,
    currentKeyId: "chain-key", currentPublicKey: signer.publicKey,
    nextKeyId: "chain-key-2", nextPublicKey: successor.publicKey,
  });
  assert.equal(transition.ok, true);
  assert.equal(
    Buffer.from(segText(transition.value.protectedSegment), "base64url").toString("utf8"),
    `{"alg":"ES256","kid":"chain-key","typ":"ba+key-transition"}`,
  );
  const trPayload = segJson(transition.value.payloadSegment) as Record<string, unknown>;
  assert.deepEqual(Object.keys(trPayload), ["chain_id", "effective_at", "from_key_fingerprint", "to_key_fingerprint", "to_key_id", "transition_id", "v"]);
  assert.equal(trPayload.v, 3);
  assert.equal(trPayload.from_key_fingerprint, signer.thumbprint);
  assert.equal(trPayload.to_key_fingerprint, successor.thumbprint);

  assert.equal(boundaryAnchorSigningInput({
    anchorId: "urn:example:anchor:x", anchoredAt: 1200, chainId: "urn:example:chain",
    sequence: 0, chainHash: sha256Of(new Uint8Array(1)), keyId: "chain-key", publicKey: signer.publicKey,
  }).ok, false, "genesis sequence 0 requires the all-zero chain hash");
  assert.equal(keyTransitionSigningInput({
    transitionId: "urn:example:transition:x", chainId: "urn:example:chain", effectiveAt: 1500,
    currentKeyId: "chain-key", currentPublicKey: signer.publicKey,
    nextKeyId: "chain-key-2", nextPublicKey: signer.publicKey,
  }).ok, false, "a transition to the same key is rejected");
});

test("v3 producer: closed-set input rejections fail value-free", () => {
  const holder = ecRawKey();
  const goodGrant = {
    keyId: "issuer-key", ...grantFixture(holder.thumbprint),
    operations: [{ name: "transfer", selectors: [{ kind: "all" } as never] }],
  };
  assert.equal(grantSigningInput({ ...goodGrant, keyId: "bad key!" } as never).ok, false);
  assert.equal(grantSigningInput({ ...goodGrant, holderThumbprint: "AA" } as never).ok, false);
  assert.equal(grantSigningInput({ ...goodGrant, holderThumbprint: "not-base64url!!" } as never).ok, false);
  assert.equal(grantSigningInput({ ...goodGrant, audiences: [] } as never).ok, false);
  assert.equal(grantSigningInput({ ...goodGrant, operations: [{ name: "transfer", selectors: [{ kind: "lte", path: ["amount"], value: { t: "string", v: strUtf8("USD") } }] }] }).ok, false, "a range selector needs a numeric bound");
  assert.equal(grantSigningInput({ ...goodGrant, operations: [{ name: "transfer", selectors: [{ kind: "bogus" } as never] }] }).ok, false);

  const goodProof = {
    holderPublicKey: holder.publicKey, proofId: "urn:example:proof:1", method: "POST",
    targetUri: `${AUDIENCE}/invoke`, issuedAt: 1500, invocationId: INVOCATION_ID,
    operation: "transfer", grantCompact: new TextEncoder().encode("aaa.bbb.ccc"), castArguments: amountArgs(),
  };
  assert.equal(proofSigningInput({ ...goodProof, invocationId: "not-a-uuid" }).ok, false);
  assert.equal(proofSigningInput({ ...goodProof, method: "PO ST" }).ok, false);
  assert.equal(proofSigningInput({ ...goodProof, targetUri: "HTTPS://resource.example.test/invoke" }).ok, false, "htu must be pre-normalized");
  assert.equal(proofSigningInput({ ...goodProof, holderPublicKey: new Uint8Array(33) }).ok, false, "compressed raw keys are invalid");
  assert.equal(proofSigningInput({ ...goodProof, grantCompact: new Uint8Array(10) }).ok, false, "a non-compact grant is not hashed into ath");

  // REQ3-KEY-point-on-curve at the producer: a 65-byte 0x04-prefixed key whose
  // coordinates are not a P-256 point is rejected before any backend call.
  const xOverPrime = new Uint8Array(65);
  xOverPrime[0] = 0x04;
  xOverPrime.set(new Uint8Array(32).fill(0xff), 1); // x ≥ p
  xOverPrime.set(holder.publicKey.subarray(33), 33);
  assert.equal(isOnCurveP256(xOverPrime.subarray(1, 33), xOverPrime.subarray(33)), false);
  assert.equal(proofSigningInput({ ...goodProof, holderPublicKey: xOverPrime }).ok, false, "x ≥ p is rejected");
  const offCurve = new Uint8Array(holder.publicKey);
  offCurve[64] = (offCurve[64] ?? 0) ^ 0x01; // a y that is not on the curve (self-checked below)
  assert.equal(isOnCurveP256(offCurve.subarray(1, 33), offCurve.subarray(33)), false, "fixture sanity: the flipped point is off-curve");
  assert.equal(proofSigningInput({ ...goodProof, holderPublicKey: offCurve }).ok, false, "an off-curve point is rejected");
});

// ---------------------------------------------------------------------------
// Low-S normalization — unit and property.

test("v3 low-S: the normalizer is one conditional subtraction (forced high-S maps back)", () => {
  const key = ecRawKey();
  const message = new TextEncoder().encode("the quick brown fox");
  const raw = new Uint8Array(ecSign("SHA256", message, { key: key.privateKey, dsaEncoding: "ieee-p1363" }));
  const low = normalizeLowS(raw); // whatever node produced, normalized

  // Force the malleable counterpart: s -> n - s.
  const forcedHigh = new Uint8Array(low);
  forcedHigh.set(bigIntTo32(P256_N - bytesToBigInt(low.subarray(32))), 32);
  assert.ok(bytesToBigInt(forcedHigh.subarray(32)) > HALF, "the forced form is high-S");

  const back = normalizeLowS(forcedHigh);
  assert.deepEqual(back, low, "normalizing the counterpart returns the original low-S encoding");
  assert.equal(es256Verifies(message, back, key.publicKey), true);

  // The identity at the ceiling: s == (n-1)/2 stays untouched.
  const atCeiling = new Uint8Array(64);
  atCeiling.set(bigIntTo32(HALF), 32);
  assert.deepEqual(normalizeLowS(atCeiling), atCeiling, "s == (n-1)/2 is already low-S");
  // Just above the ceiling maps to exactly (n-1)/2.
  const above = new Uint8Array(64);
  above.set(bigIntTo32(HALF + 1n), 32);
  assert.equal(bytesToBigInt(normalizeLowS(above).subarray(32)), HALF);
});

test("v3 low-S property: fresh keys, every emitted s <= (n-1)/2, every signature verifies (raw + DER)", async () => {
  const issuer = ecRawKey();
  const grant = await signV3Grant(
    grantFixture(ecRawKey().thumbprint),
    ecHandleFor(issuer, { keyId: "issuer-key", role: "issuer" }),
  );
  assert.equal(grant.ok, true, `fixture grant signing failed: ${JSON.stringify(grant)}`);

  const ITERATIONS = 120; // >= 50 required; the natural high-S rate is ~1/2
  let naturalHigh = 0;
  let naturalLow = 0;
  for (let i = 0; i < ITERATIONS; i++) {
    const holder: EcRawKey = ecRawKey();
    const rawSignatures: Uint8Array[] = [];
    const envelope = await signV3Report(
      {
        grantCompact: grant.value.grant, operation: "transfer", method: "POST",
        targetUri: `${AUDIENCE}/invoke`, invocationId: INVOCATION_ID, castArguments: amountArgs(),
      },
      ecHandleFor(holder, { keyId: "holder-key", rawSignatures }),
      { issuedAt: 1500, proofId: "urn:example:proof:p" },
    );
    assert.equal(envelope.ok, true, `iteration ${i}: ${JSON.stringify(envelope)}`);

    const [head, body, sigSeg] = segments(envelope.value.proof);
    // Canonical unpadded base64url signature segment.
    assert.equal(Buffer.from(decodeBytes(sigSeg)).toString("base64url"), sigSeg);
    const emitted = decodeBytes(sigSeg);
    assert.equal(emitted.length, 64);

    const r = bytesToBigInt(emitted.subarray(0, 32));
    const s = bytesToBigInt(emitted.subarray(32));
    assert.ok(s > 0n && s <= HALF, `iteration ${i}: emitted s must satisfy 0 < s <= (n-1)/2`);
    assert.ok(r > 0n && r < P256_N, `iteration ${i}: emitted r must satisfy 0 < r < n`);

    // The emitted encoding is exactly the handle's raw signature, or its
    // low-S counterpart — the normalizer is the only difference.
    const rawSig = rawSignatures[0];
    assert.ok(rawSig !== undefined, "the handle signed exactly once");
    const rawS = bytesToBigInt(rawSig.subarray(32));
    if (rawS > HALF) {
      naturalHigh += 1;
      assert.equal(s, P256_N - rawS, `iteration ${i}: high-S raw was normalized to n - s`);
      assert.deepEqual(emitted.subarray(0, 32), rawSig.subarray(0, 32), "r is untouched");
    } else {
      naturalLow += 1;
      assert.deepEqual(emitted, rawSig, `iteration ${i}: an already-low s passes through`);
    }

    // Crypto-level verification, twice: raw ieee-p1363 AND DER re-encoded.
    const message = new TextEncoder().encode(`${head}.${body}`);
    const pub = ecPublic(holder);
    assert.equal(ecVerify("SHA256", message, { key: pub, dsaEncoding: "ieee-p1363" }, Buffer.from(emitted)), true, `iteration ${i}: emitted signature verifies (raw)`);
    assert.equal(ecVerify("SHA256", message, pub, derFromRaw(emitted)), true, `iteration ${i}: emitted (r, s) re-encoded as DER verifies`);
  }
  assert.ok(naturalHigh > 0, "the sample must contain at least one natural high-S (rate ~1/2)");
  console.log(`v3 low-S property run: ${ITERATIONS} signatures, ${naturalHigh} natural high-S normalized, ${naturalLow} natural low-S`);
});

test("v3 low-S: malleability is live on the backend — and excluded from the emitted set by construction", () => {
  const key = ecRawKey();
  const message = new TextEncoder().encode("evidence bytes");
  const raw = new Uint8Array(ecSign("SHA256", message, { key: key.privateKey, dsaEncoding: "ieee-p1363" }));
  const low = normalizeLowS(raw);

  const counterpart = new Uint8Array(low);
  counterpart.set(bigIntTo32(P256_N - bytesToBigInt(low.subarray(32))), 32);
  // The backend ACCEPTS the counterpart (ECDSA malleability, OBSERVED) — the
  // reason the profile needs low-S at all.
  assert.equal(es256Verifies(message, counterpart, key.publicKey), true);
  // And the normalizer maps the counterpart back to the one admissible encoding.
  assert.deepEqual(normalizeLowS(counterpart), low);
});

// ---------------------------------------------------------------------------
// The four signers — API shape, gates, and the byte-level signature pinning.

test("v3 signers: issuer grant -> holder report; every compact's signature pinned at the byte level", async () => {
  const issuer = ecRawKey();
  const holder = ecRawKey();

  const grant = await signV3Grant(grantFixture(holder.thumbprint), ecHandleFor(issuer, { keyId: "issuer-key", role: "issuer" }));
  assert.equal(grant.ok, true, `grant signing failed: ${JSON.stringify(grant)}`);

  const [grantHead, grantBody, grantSig] = segments(grant.value.grant);
  const grantHeader = decodeSegment(grantHead) as { alg: string; kid: string; typ: string };
  assert.deepEqual(grantHeader, { alg: "ES256", kid: "issuer-key", typ: "ba+cap" });
  const grantPayload = decodeSegment(grantBody) as { v: number; cnf: { jkt: string } };
  assert.equal(grantPayload.v, 3);
  assert.equal(grantPayload.cnf.jkt, holder.thumbprint);
  assert.equal(
    ecVerify("SHA256", new TextEncoder().encode(`${grantHead}.${grantBody}`), { key: ecPublic(issuer), dsaEncoding: "ieee-p1363" }, Buffer.from(decodeBytes(grantSig))),
    true,
    "the grant signature verifies over the exact RFC 7515 signing input",
  );

  const envelope = await signV3Report(
    {
      grantCompact: grant.value.grant, operation: "transfer", method: "POST",
      targetUri: `${AUDIENCE}/invoke`, invocationId: INVOCATION_ID, castArguments: amountArgs(),
    },
    ecHandleFor(holder, { keyId: "holder-key" }),
    { issuedAt: 1500, proofId: "urn:example:proof:1" },
  );
  assert.equal(envelope.ok, true, `report signing failed: ${JSON.stringify(envelope)}`);
  assert.deepEqual(envelope.value.grant, grant.value.grant, "the grant passes through untouched");

  const [proofHead, proofBody, proofSig] = segments(envelope.value.proof);
  const header = decodeSegment(proofHead) as { alg: string; typ: string; jwk: { crv: string; kty: string; x: string; y: string } };
  assert.equal(header.alg, "ES256");
  assert.equal(header.typ, "dpop+jwt");
  assert.deepEqual(header.jwk, { crv: "P-256", kty: "EC", x: holder.jwk.x, y: holder.jwk.y });

  const proofPayload = decodeSegment(proofBody) as { v: number; ath: string };
  assert.equal(proofPayload.v, 3);
  assert.equal(proofPayload.ath, b64(sha256Of(grant.value.grant)), "ath is SHA-256 of the exact grant compact");

  const signature = decodeBytes(proofSig);
  assert.equal(signature.length, 64);
  assert.ok(bytesToBigInt(signature.subarray(32)) <= HALF, "the wire signature is low-S");
  const proofMessage = new TextEncoder().encode(`${proofHead}.${proofBody}`);
  assert.equal(ecVerify("SHA256", proofMessage, { key: ecPublic(holder), dsaEncoding: "ieee-p1363" }, Buffer.from(signature)), true);
  assert.equal(ecVerify("SHA256", proofMessage, ecPublic(holder), derFromRaw(signature)), true, "DER re-encode verifies");
});

test("v3 signers: anchor and key transition verify at the crypto level", async () => {
  const signer = ecRawKey();
  const successor = ecRawKey();

  const anchor = await signV3Anchor(
    { anchorId: "urn:example:anchor:start", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) },
    ecHandleFor(signer, { keyId: "chain-key" }),
    { anchoredAt: 1200 },
  );
  assert.equal(anchor.ok, true, `anchor signing failed: ${JSON.stringify(anchor)}`);
  const [aHead, aBody, aSig] = segments(anchor.value.anchor);
  const aPayload = decodeSegment(aBody) as { v: number; key_fingerprint: string };
  assert.equal(aPayload.v, 3);
  assert.equal(aPayload.key_fingerprint, signer.thumbprint);
  assert.equal(ecVerify("SHA256", new TextEncoder().encode(`${aHead}.${aBody}`), { key: ecPublic(signer), dsaEncoding: "ieee-p1363" }, Buffer.from(decodeBytes(aSig))), true);

  const transition = await signV3KeyTransition(
    {
      transitionId: "urn:example:transition:1", chainId: "urn:example:chain", effectiveAt: 1500,
      nextKeyId: "chain-key-2", nextPublicKey: successor.publicKey,
    },
    ecHandleFor(signer, { keyId: "chain-key" }),
  );
  assert.equal(transition.ok, true, `transition signing failed: ${JSON.stringify(transition)}`);
  const [tHead, tBody, tSig] = segments(transition.value.keyTransition);
  const trPayload = decodeSegment(tBody) as { v: number; from_key_fingerprint: string; to_key_fingerprint: string };
  assert.equal(trPayload.v, 3);
  assert.equal(trPayload.from_key_fingerprint, signer.thumbprint);
  assert.equal(trPayload.to_key_fingerprint, successor.thumbprint);
  assert.equal(ecVerify("SHA256", new TextEncoder().encode(`${tHead}.${tBody}`), { key: ecPublic(signer), dsaEncoding: "ieee-p1363" }, Buffer.from(decodeBytes(tSig))), true);
});

test("v3 gates: the C1 role gate — a holder handle cannot sign a grant, and sign() is never called", async () => {
  const calls = { count: 0 };
  const r = await signV3Grant(
    grantFixture(ecRawKey().thumbprint),
    ecHandleFor(ecRawKey(), { keyId: "holder-key", role: "holder", signCalls: calls }),
  );
  assert.equal(r.ok, false);
  assert.equal((r as { error: string }).error, "invalid_key_handle");
  assert.equal(calls.count, 0, "the C1 gate must reject BEFORE calling sign()");

  const noIdentity = await signV3Grant(grantFixture(ecRawKey().thumbprint), ecHandleFor(ecRawKey(), { keyId: "k" }));
  assert.equal((noIdentity as { error: string }).error, "invalid_key_handle");
});

test("v3 gates: a handle signing with the wrong EC key fails closed as signing_failed", async () => {
  const grant = await signV3Grant(grantFixture(ecRawKey().thumbprint), ecHandleFor(ecRawKey(), { keyId: "issuer-key", role: "issuer" }));
  assert.equal(grant.ok, true);

  const reported = ecRawKey();
  const actual = ecRawKey();
  const r = await signV3Report(
    {
      grantCompact: grant.value.grant, operation: "transfer", method: "POST",
      targetUri: `${AUDIENCE}/invoke`, invocationId: INVOCATION_ID, castArguments: amountArgs(),
    },
    ecHandleFor(reported, { keyId: "holder-key", wrongSigningKey: actual }),
    { issuedAt: 1500, proofId: "urn:example:proof:w" },
  );
  assert.equal(r.ok, false);
  assert.equal((r as { error: string }).error, "signing_failed");
});

test("v3 gates: malformed inputs map to the closed error codes", async () => {
  const holder = ecHandleFor(ecRawKey(), { keyId: "k" });
  assert.equal(((await signV3Report({} as never, holder, {})) as { error: string }).error, "invalid_report");
  assert.equal(((await signV3Anchor({ anchorId: "a", chainId: "c", sequence: 1.5, chainHash: new Uint8Array(32) }, holder, {})) as { error: string }).error, "invalid_anchor");
  assert.equal(((await signV3Grant({ ...grantFixture("AA"), issuedAt: "nope" } as never, ecHandleFor(ecRawKey(), { keyId: "k", role: "issuer" }), {})) as { error: string }).error, "invalid_grant");
  assert.equal(((await signV3KeyTransition({ transitionId: "t", chainId: "c", effectiveAt: 1, nextKeyId: "n", nextPublicKey: new Uint8Array(33) }, holder, {})) as { error: string }).error, "invalid_transition");
  // A 33-byte (compressed-looking) holder public key is invalid_key_handle.
  const compressed = ecHandleFor(ecRawKey(), { keyId: "k" }) as { publicKey: () => Uint8Array };
  compressed.publicKey = () => new Uint8Array(33);
  assert.equal(((await signV3Report({
    grantCompact: new Uint8Array(10), operation: "transfer", method: "POST",
    targetUri: `${AUDIENCE}/invoke`, invocationId: INVOCATION_ID, castArguments: amountArgs(),
  }, compressed as never, {})) as { error: string }).error, "invalid_key_handle");
  // Producer rejections surface as producer_error (non-canonical htu).
  assert.equal(((await signV3Report({
    grantCompact: new TextEncoder().encode("aaa.bbb.ccc"), operation: "transfer", method: "POST",
    targetUri: "HTTPS://x.example.test/invoke", invocationId: INVOCATION_ID, castArguments: amountArgs(),
  }, ecHandleFor(ecRawKey(), { keyId: "k" }), { issuedAt: 1500, proofId: "urn:example:proof:x" })) as { error: string }).error, "producer_error");
});
