// The runtime-neutral sign-then-verify battery (laws L2 and L3 of the browser-safe design), run in
// every lane: Node 22 and 24 (verifier backend "node"), Node with --conditions=bap-portable, Deno, Bun
// and real browsers (backend "portable"). Pure: generated keys, the signer source, the verifier package,
// no I/O and no Node API. Each check compares VERDICTS through the verifier package, never signature
// bytes across engines.
//
// L2: v1 signReport (and the loopback profile), v2 signV2Report, v3 signV3Report, plus each major's
//     grant, anchor and key transition, are accepted by the verifier with matching expected context; a
//     handle signing with a different key returns signing_failed on every major.
// L3: over TRIALS v3 reports from a handle that emits high-S about half the time, every emitted s is in
//     (0, (n-1)/2], r is untouched, a high raw s becomes n - s, a low one passes through, and every
//     envelope verifies; normalizeLowS is idempotent, the identity on low-S, and refuses r or s outside
//     (0, n).
import {
  base64urlDecode,
  checkEnvelope,
  checkLocalLoopbackHttpEnvelope,
  publicKeyThumbprintRaw,
  strUtf8,
  verifyHistoricalAnchor,
  verifyKeyTransition,
  v2,
  v3,
  type Tagged,
} from "@bounded-authority-protocol/verifier";
import {
  signAnchor, signGrant, signKeyTransition, signLocalLoopbackReport, signReport,
  signV2Anchor, signV2Grant, signV2KeyTransition, signV2Report,
  signV3Anchor, signV3Grant, signV3KeyTransition, signV3Report,
} from "../../src/index.js";
import { P256_HALF_ORDER, P256_ORDER, normalizeLowS } from "../../src/es256.js";
import { ecHandle, ecKey, edHandle, edKey } from "./keys.js";

export const TRIALS = 64;

const ISS = "https://issuer.example.test";
const AUD = "https://resource.example.test";
const TARGET = `${AUD}/invoke`;
const LOOPBACK = "http://127.0.0.1:8080/invoke";
const INV = "550e8400-e29b-41d4-a716-446655440000";
const args = (): Tagged => ({ t: "object", v: new Map([["amount", { t: "int", v: 5000 }]]) });
const report = (grantCompact: Uint8Array, targetUri = TARGET) => ({ grantCompact, operation: "transfer", method: "POST", targetUri, invocationId: INV, castArguments: args() });
const grantInput = (holderThumbprint: string, selectors: never[]) => ({
  issuer: ISS, grantId: "urn:example:grant:l2", audiences: [AUD], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint, operations: [{ name: "transfer", selectors }],
});
const ALL = [{ kind: "all" }] as never[];
const LTE = [{ kind: "lte", path: ["amount"], value: { t: "int", v: 10_000 } }] as never[];
const expected = (publicKey: Uint8Array, targetUri = TARGET, nonce: { kind: "not_required" } | { kind: "required"; value: string } = { kind: "not_required" }) => ({
  trustedIssuer: { keyId: "issuer-key", publicKey }, issuer: ISS, audience: AUD, method: "POST", targetUri,
  invocationId: INV, operation: "transfer", castArguments: args(), evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300, nonce,
});
const opts = { issuedAt: 1500, proofId: "urn:example:proof:l2" };
const histKey = (keyId: string, publicKey: Uint8Array, validFrom = 0) => ({ keyId, publicKey, validFrom, validBefore: null });

const bytesToBigInt = (bytes: Uint8Array): bigint => {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
};
const signatureOf = (compact: Uint8Array): Uint8Array => {
  const text = new TextDecoder().decode(compact);
  return base64urlDecode(strUtf8(text.slice(text.lastIndexOf(".") + 1)));
};
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

export interface L2Report {
  readonly checks: Record<string, boolean>;
  readonly trials: number;
  readonly highS: number;
}

export async function runL2(options: { secure: boolean }): Promise<L2Report> {
  const checks: Record<string, boolean> = {};

  // ---- contract-major 1 ----
  {
    const issuer = edKey();
    const holder = edKey();
    const g = await signGrant(grantInput(holder.thumbprint, ALL), edHandle(issuer, { keyId: "issuer-key", role: "issuer" }));
    const e = g.ok ? await signReport(report(g.value.grant), edHandle(holder, { keyId: "holder-key" }), opts) : g;
    checks["v1 signReport -> checkEnvelope"] = e.ok && checkEnvelope(e.value.grant, e.value.proof, expected(issuer.publicKey)).ok;
    const lb = g.ok ? await signLocalLoopbackReport({ ...report(g.value.grant, LOOPBACK), nonce: "n-1" }, edHandle(holder, { keyId: "holder-key" }), opts) : g;
    checks["v1 signLocalLoopbackReport -> checkLocalLoopbackHttpEnvelope"] = lb.ok &&
      checkLocalLoopbackHttpEnvelope(lb.value.grant, lb.value.proof, expected(issuer.publicKey, LOOPBACK, { kind: "required", value: "n-1" })).ok;
    const wrong = g.ok ? await signReport(report(g.value.grant), edHandle(holder, { keyId: "holder-key", signWith: edKey() }), opts) : g;
    checks["v1 wrong-key handle -> signing_failed"] = !wrong.ok && wrong.error === "signing_failed";
    if (options.secure) {
      const d = g.ok ? await signReport(report(g.value.grant), edHandle(holder, { keyId: "holder-key" }), { issuedAt: 1500 }) : g;
      checks["v1 default proofId (secure context) -> checkEnvelope"] = d.ok && checkEnvelope(d.value.grant, d.value.proof, expected(issuer.publicKey)).ok;
    }
    const chain = edKey();
    const next = edKey();
    const a = await signAnchor({ anchorId: "urn:example:anchor:1", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) }, edHandle(chain, { keyId: "chain-key" }), { anchoredAt: 1200 });
    checks["v1 signAnchor -> verifyHistoricalAnchor"] = a.ok && verifyHistoricalAnchor(a.value.anchor, histKey("chain-key", chain.publicKey), {
      anchorId: "urn:example:anchor:1", chainId: "urn:example:chain", keyId: "chain-key", sequence: 0, anchoredAt: 1200,
      chainHash: new Uint8Array(32), keyFingerprint: publicKeyThumbprintRaw(chain.publicKey),
    }).ok;
    const t = await signKeyTransition({ transitionId: "urn:example:transition:1", chainId: "urn:example:chain", effectiveAt: 1500, nextKeyId: "chain-key-2", nextPublicKey: next.publicKey }, edHandle(chain, { keyId: "chain-key" }));
    checks["v1 signKeyTransition -> verifyKeyTransition"] = t.ok && verifyKeyTransition(t.value.keyTransition, histKey("chain-key", chain.publicKey), histKey("chain-key-2", next.publicKey, 1500), {
      transitionId: "urn:example:transition:1", chainId: "urn:example:chain", effectiveAt: 1500,
      currentKeyFingerprint: publicKeyThumbprintRaw(chain.publicKey), nextKeyFingerprint: publicKeyThumbprintRaw(next.publicKey),
      currentKeyId: "chain-key", nextKeyId: "chain-key-2",
    }).ok;
  }

  // ---- contract-major 2 ----
  {
    const issuer = edKey();
    const holder = edKey();
    const g = await signV2Grant(grantInput(holder.thumbprint, LTE), edHandle(issuer, { keyId: "issuer-key", role: "issuer" }));
    const e = g.ok ? await signV2Report(report(g.value.grant), edHandle(holder, { keyId: "holder-key" }), opts) : g;
    checks["v2 signV2Report -> v2.checkEnvelope"] = e.ok && v2.checkEnvelope(e.value.grant, e.value.proof, expected(issuer.publicKey)).ok;
    checks["v2 envelope refused by v1 checkEnvelope"] = e.ok && !checkEnvelope(e.value.grant, e.value.proof, expected(issuer.publicKey)).ok;
    const wrong = g.ok ? await signV2Report(report(g.value.grant), edHandle(holder, { keyId: "holder-key", signWith: edKey() }), opts) : g;
    checks["v2 wrong-key handle -> signing_failed"] = !wrong.ok && wrong.error === "signing_failed";
    const chain = edKey();
    const next = edKey();
    const a = await signV2Anchor({ anchorId: "urn:example:anchor:2", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) }, edHandle(chain, { keyId: "chain-key" }), { anchoredAt: 1200 });
    checks["v2 signV2Anchor -> v2.verifyHistoricalAnchor"] = a.ok && v2.verifyHistoricalAnchor(a.value.anchor, histKey("chain-key", chain.publicKey), {
      anchorId: "urn:example:anchor:2", chainId: "urn:example:chain", keyId: "chain-key", sequence: 0, anchoredAt: 1200,
      chainHash: new Uint8Array(32), keyFingerprint: publicKeyThumbprintRaw(chain.publicKey),
    }).ok;
    const t = await signV2KeyTransition({ transitionId: "urn:example:transition:2", chainId: "urn:example:chain", effectiveAt: 1500, nextKeyId: "chain-key-2", nextPublicKey: next.publicKey }, edHandle(chain, { keyId: "chain-key" }));
    checks["v2 signV2KeyTransition -> v2.verifyKeyTransition"] = t.ok && v2.verifyKeyTransition(t.value.keyTransition, histKey("chain-key", chain.publicKey), histKey("chain-key-2", next.publicKey, 1500), { // gitleaks:allow (test label, not a secret)
      transitionId: "urn:example:transition:2", chainId: "urn:example:chain", effectiveAt: 1500,
      currentKeyFingerprint: publicKeyThumbprintRaw(chain.publicKey), nextKeyFingerprint: publicKeyThumbprintRaw(next.publicKey),
      currentKeyId: "chain-key", nextKeyId: "chain-key-2",
    }).ok;
  }

  // ---- contract-major 3, and L3 over TRIALS reports ----
  let highS = 0;
  {
    const issuer = ecKey();
    const chain = ecKey();
    const next = ecKey();
    const fp = (thumbprint: string) => base64urlDecode(strUtf8(thumbprint));
    const a = await signV3Anchor({ anchorId: "urn:example:anchor:3", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) }, ecHandle(chain, { keyId: "chain-key" }), { anchoredAt: 1200 });
    checks["v3 signV3Anchor -> v3.verifyHistoricalAnchor"] = a.ok && v3.verifyHistoricalAnchor(a.value.anchor, histKey("chain-key", chain.publicKey), {
      anchorId: "urn:example:anchor:3", chainId: "urn:example:chain", keyId: "chain-key", sequence: 0, anchoredAt: 1200,
      chainHash: new Uint8Array(32), keyFingerprint: fp(chain.thumbprint),
    }).ok;
    const t = await signV3KeyTransition({ transitionId: "urn:example:transition:3", chainId: "urn:example:chain", effectiveAt: 1500, nextKeyId: "chain-key-2", nextPublicKey: next.publicKey }, ecHandle(chain, { keyId: "chain-key" }));
    checks["v3 signV3KeyTransition -> v3.verifyKeyTransition"] = t.ok && v3.verifyKeyTransition(t.value.keyTransition, histKey("chain-key", chain.publicKey), histKey("chain-key-2", next.publicKey, 1500), { // gitleaks:allow (test label, not a secret)
      transitionId: "urn:example:transition:3", chainId: "urn:example:chain", effectiveAt: 1500,
      currentKeyFingerprint: fp(chain.thumbprint), nextKeyFingerprint: fp(next.thumbprint), currentKeyId: "chain-key", nextKeyId: "chain-key-2",
    }).ok;

    let allVerify = true;
    let allLowS = true;
    let normalizedExactly = true;
    for (let i = 0; i < TRIALS; i++) {
      const holder = ecKey();
      const raw: Uint8Array[] = [];
      const g = await signV3Grant(grantInput(holder.thumbprint, ALL), ecHandle(issuer, { keyId: "issuer-key", role: "issuer" }));
      const e = g.ok ? await signV3Report(report(g.value.grant), ecHandle(holder, { keyId: "holder-key", raw }), opts) : g;
      if (!e.ok || raw.length !== 1) { allVerify = false; continue; }
      allVerify &&= v3.checkEnvelope(e.value.grant, e.value.proof, expected(issuer.publicKey)).ok;
      const emitted = signatureOf(e.value.proof);
      const s = bytesToBigInt(emitted.subarray(32));
      const rawS = bytesToBigInt(raw[0]!.subarray(32));
      allLowS &&= s > 0n && s <= P256_HALF_ORDER && equal(emitted.subarray(0, 32), raw[0]!.subarray(0, 32));
      if (rawS > P256_HALF_ORDER) {
        highS += 1;
        normalizedExactly &&= s === P256_ORDER - rawS;
      } else {
        normalizedExactly &&= equal(emitted, raw[0]!);
      }
    }
    checks[`v3 signV3Report x${TRIALS} -> v3.checkEnvelope`] = allVerify;
    checks["L3 every emitted s in (0, (n-1)/2], r untouched"] = allLowS;
    checks["L3 high raw s -> n - s, low raw s passes through"] = normalizedExactly;
    checks["L3 the sample contains high-S raw signatures"] = highS > 0;

    const holder = ecKey();
    const g = await signV3Grant(grantInput(holder.thumbprint, ALL), ecHandle(issuer, { keyId: "issuer-key", role: "issuer" }));
    const wrong = g.ok ? await signV3Report(report(g.value.grant), ecHandle(holder, { keyId: "holder-key", signWith: ecKey() }), opts) : g;
    checks["v3 wrong-key handle -> signing_failed"] = !wrong.ok && wrong.error === "signing_failed";
    // A worker-style handle transfers (detaches) the message it is given; the library signs from its own copy.
    const transferring = { ...ecHandle(holder, { keyId: "holder-key" }), sign: (m: Uint8Array) => holder.sign(structuredClone(m, { transfer: [m.buffer as ArrayBuffer] })) };
    const moved = g.ok ? await signV3Report(report(g.value.grant), transferring, opts) : g;
    checks["v3 transferring (worker-style) handle -> v3.checkEnvelope"] = moved.ok && v3.checkEnvelope(moved.value.grant, moved.value.proof, expected(issuer.publicKey)).ok;
    // A handle that rewrites the message it is given and signs the rewritten bytes never gets ok.
    const rewriting = { ...ecHandle(holder, { keyId: "holder-key" }), sign: (m: Uint8Array) => { m[0] = (m[0] ?? 0) ^ 1; return holder.sign(m); } };
    const rewritten = g.ok ? await signV3Report(report(g.value.grant), rewriting, opts) : g;
    checks["v3 message-rewriting handle -> signing_failed"] = !rewritten.ok && rewritten.error === "signing_failed";
  }

  // ---- L3: normalizeLowS algebra ----
  {
    const key = ecKey();
    const message = new TextEncoder().encode("l3");
    let idempotent = true;
    for (let i = 0; i < 16; i++) {
      const once = normalizeLowS(key.sign(message));
      idempotent &&= equal(normalizeLowS(once), once) && bytesToBigInt(once.subarray(32)) <= P256_HALF_ORDER;
    }
    checks["L3 normalizeLowS is idempotent and lands in low-S"] = idempotent;
    const rs = (r: bigint, s: bigint) => {
      const out = new Uint8Array(64);
      for (let i = 0; i < 32; i++) {
        out[31 - i] = Number((r >> BigInt(8 * i)) & 0xffn);
        out[63 - i] = Number((s >> BigInt(8 * i)) & 0xffn);
      }
      return out;
    };
    const refuses = (r: bigint, s: bigint) => { try { normalizeLowS(rs(r, s)); return false; } catch { return true; } };
    checks["L3 normalizeLowS refuses r or s outside (0, n)"] = refuses(0n, 1n) && refuses(P256_ORDER, 1n) && refuses(1n, 0n) && refuses(1n, P256_ORDER);
    checks["L3 normalizeLowS is the identity on low-S"] = equal(normalizeLowS(rs(1n, P256_HALF_ORDER)), rs(1n, P256_HALF_ORDER));
  }

  return { checks, trials: TRIALS, highS };
}
