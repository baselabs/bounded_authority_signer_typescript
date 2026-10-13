// Handle misbehavior on every major (v1 Ed25519, v2 Ed25519, v3 ES256). The library must never return ok
// for bytes the verifier would reject, and no handle or listener misbehavior may escape as an exception:
//   m1. a handle that rewrites the message buffer it is given, then signs the rewritten bytes:
//       signing_failed (the post-sign check runs over the library's own copy of the message).
//   m2. a handle that rewrites the public-key array it reported, then signs with the other key:
//       signing_failed (resolvers keep their own copy of the key).
//   m3. a worker-style handle that transfers (detaches) the message buffer it is given: still signs,
//       and the verifier accepts the result.
//   m4. keyIdentity() returning null, a throwing keyId / publicKey / role getter, and a Proxy-wrapped
//       key: the closed invalid_key_handle, never a thrown TypeError.
//   m5. an onEvent listener that throws: the call still returns its result (ok, or its closed error).
//   m6. operations: [null] gives the same closed error on v1, v2 and v3.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkEnvelope, v2, v3 } from "@bounded-authority-protocol/verifier";
import {
  signAnchor, signGrant, signKeyTransition, signReport,
  signV2Anchor, signV2Grant, signV2KeyTransition, signV2Report,
  signV3Anchor, signV3Grant, signV3KeyTransition, signV3Report,
  type Es256KeyHandle, type KeyHandle,
} from "../src/index.js";
import { ecHandle, ecKey, edHandle, edKey, type EcKey, type EdKey } from "./lanes/keys.js";
import { amountArgs } from "./helpers.js";

const ISS = "https://issuer.example.test";
const AUD = "https://resource.example.test";
const INV = "550e8400-e29b-41d4-a716-446655440000";
const opts = { issuedAt: 1500, proofId: "urn:example:proof:m" };
const grantInput = (holderThumbprint: string, operations: unknown = [{ name: "transfer", selectors: [{ kind: "all" }] }]) => ({
  issuer: ISS, grantId: "urn:example:grant:m", audiences: [AUD], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint, operations: operations as never,
});
const report = (grantCompact: Uint8Array) => ({ grantCompact, operation: "transfer", method: "POST", targetUri: `${AUD}/invoke`, invocationId: INV, castArguments: amountArgs() });
const expected = (publicKey: Uint8Array) => ({
  trustedIssuer: { keyId: "issuer-key", publicKey }, issuer: ISS, audience: AUD, method: "POST", targetUri: `${AUD}/invoke`,
  invocationId: INV, operation: "transfer", castArguments: amountArgs(), evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300,
  nonce: { kind: "not_required" as const },
});
const anchorInput = { anchorId: "urn:example:anchor:m", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) };
const transitionInput = (next: Uint8Array) => ({ transitionId: "urn:example:transition:m", chainId: "urn:example:chain", effectiveAt: 1500, nextKeyId: "next", nextPublicKey: next });

type AnyKey = EdKey | EcKey;
type Handle = KeyHandle & Es256KeyHandle;

// One description per major: key generation, a handle, the report, grant, anchor and transition
// signers, and the verifier's envelope check.
interface Major {
  readonly name: string;
  key(): AnyKey;
  handle(key: AnyKey, opts: { keyId: string; role?: "issuer" | "holder" }): Handle;
  signReport(r: ReturnType<typeof report>, h: Handle, o?: object): Promise<{ ok: boolean; error?: string; value?: { grant: Uint8Array; proof: Uint8Array } }>;
  signGrant(g: ReturnType<typeof grantInput>, h: Handle, o?: object): Promise<{ ok: boolean; error?: string; value?: { grant: Uint8Array } }>;
  signAnchor(h: Handle, o?: object): Promise<{ ok: boolean; error?: string }>;
  signTransition(h: Handle, next: Uint8Array): Promise<{ ok: boolean; error?: string }>;
  check(grant: Uint8Array, proof: Uint8Array, issuer: Uint8Array): boolean;
}

const MAJORS: readonly Major[] = [
  {
    name: "v1", key: edKey, handle: (k, o) => edHandle(k as EdKey, o) as Handle,
    signReport: (r, h, o) => signReport(r, h, o), signGrant: (g, h, o) => signGrant(g, h, o),
    signAnchor: (h, o) => signAnchor(anchorInput, h, { anchoredAt: 1200, ...o }), signTransition: (h, n) => signKeyTransition(transitionInput(n), h),
    check: (g, p, i) => checkEnvelope(g, p, expected(i)).ok,
  },
  {
    name: "v2", key: edKey, handle: (k, o) => edHandle(k as EdKey, o) as Handle,
    signReport: (r, h, o) => signV2Report(r, h, o), signGrant: (g, h, o) => signV2Grant(g, h, o),
    signAnchor: (h, o) => signV2Anchor(anchorInput, h, { anchoredAt: 1200, ...o }), signTransition: (h, n) => signV2KeyTransition(transitionInput(n), h),
    check: (g, p, i) => v2.checkEnvelope(g, p, expected(i)).ok,
  },
  {
    name: "v3", key: ecKey, handle: (k, o) => ecHandle(k as EcKey, o) as Handle,
    signReport: (r, h, o) => signV3Report(r, h, o), signGrant: (g, h, o) => signV3Grant(g as never, h, o),
    signAnchor: (h, o) => signV3Anchor(anchorInput, h, { anchoredAt: 1200, ...o }), signTransition: (h, n) => signV3KeyTransition(transitionInput(n), h),
    check: (g, p, i) => v3.checkEnvelope(g, p, expected(i)).ok,
  },
];

async function fixture(m: Major) {
  const issuer = m.key();
  const holder = m.key();
  const g = await m.signGrant(grantInput(holder.thumbprint), m.handle(issuer, { keyId: "issuer-key", role: "issuer" }));
  assert.equal(g.ok, true, `${m.name} fixture grant`);
  return { issuer, holder, grant: g.value!.grant };
}

// Never throws: the result, or "threw: <name>".
async function settle<T>(run: () => Promise<T>): Promise<T | string> {
  try {
    return await run();
  } catch (e) {
    return `threw: ${e instanceof Error ? e.name : typeof e}`;
  }
}

for (const m of MAJORS) {
  test(`m1 ${m.name}: a handle that rewrites the message it is given and signs the rewritten bytes gets signing_failed`, async () => {
    const { holder, grant } = await fixture(m);
    const h: Handle = {
      ...m.handle(holder, { keyId: "holder-key" }),
      sign: (msg: Uint8Array) => {
        msg[msg.length - 1] = (msg[msg.length - 1] ?? 0) ^ 0x01; // a different message, signed with the right key
        return holder.sign(msg);
      },
    };
    assert.deepEqual(await settle(() => m.signReport(report(grant), h, opts)), { ok: false, error: "signing_failed" });
  });

  test(`m1 ${m.name}: a handle that rewrites the message only after signing it still signs, and the verifier accepts`, async () => {
    const { issuer, holder, grant } = await fixture(m);
    const h: Handle = {
      ...m.handle(holder, { keyId: "holder-key" }),
      sign: (msg: Uint8Array) => {
        const sig = holder.sign(msg);
        msg.fill(0);
        return sig;
      },
    };
    const r = await m.signReport(report(grant), h, opts);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(m.check(r.value!.grant, r.value!.proof, issuer.publicKey), true);
  });

  test(`m2 ${m.name}: a handle that rewrites its reported public key, then signs with the other key, gets signing_failed`, async () => {
    const { holder, grant } = await fixture(m);
    const other = m.key();
    const reported = new Uint8Array(holder.publicKey);
    const h: Handle = {
      ...m.handle(holder, { keyId: "holder-key" }),
      publicKey: () => reported,
      sign: (msg: Uint8Array) => {
        reported.set(other.publicKey);
        return other.sign(msg);
      },
    };
    assert.deepEqual(await settle(() => m.signReport(report(grant), h, opts)), { ok: false, error: "signing_failed" });
  });

  test(`m2 ${m.name}: the same rewrite through signingIdentity() (grant) and keyIdentity() (anchor) gets signing_failed`, async () => {
    const issuer = m.key();
    const other = m.key();
    const reported = new Uint8Array(issuer.publicKey);
    const h: Handle = {
      ...m.handle(issuer, { keyId: "issuer-key", role: "issuer" }),
      signingIdentity: () => ({ role: "issuer", keyId: "issuer-key", publicKey: reported }),
      keyIdentity: () => ({ keyId: "issuer-key", publicKey: reported }),
      sign: (msg: Uint8Array) => {
        reported.set(other.publicKey);
        return other.sign(msg);
      },
    };
    assert.deepEqual(await settle(() => m.signGrant(grantInput(m.key().thumbprint), h)), { ok: false, error: "signing_failed" });
    reported.set(issuer.publicKey);
    assert.deepEqual(await settle(() => m.signAnchor(h)), { ok: false, error: "signing_failed" });
  });

  test(`m3 ${m.name}: a worker-style handle that transfers (detaches) the message buffer still signs, and the verifier accepts`, async () => {
    const { issuer, holder, grant } = await fixture(m);
    const h: Handle = {
      ...m.handle(holder, { keyId: "holder-key" }),
      sign: async (msg: Uint8Array) => {
        const moved = structuredClone(msg, { transfer: [msg.buffer as ArrayBuffer] });
        assert.equal(msg.byteLength, 0, "the given buffer is detached");
        return holder.sign(moved);
      },
    };
    const r = await m.signReport(report(grant), h, opts);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(m.check(r.value!.grant, r.value!.proof, issuer.publicKey), true);
  });

  test(`m4 ${m.name}: keyIdentity() returning null is invalid_key_handle for anchors and transitions`, async () => {
    const k = m.key();
    const h: Handle = { ...m.handle(k, { keyId: "k" }), keyIdentity: () => null as never };
    assert.deepEqual(await settle(() => m.signAnchor(h)), { ok: false, error: "invalid_key_handle" });
    assert.deepEqual(await settle(() => m.signTransition(h, m.key().publicKey)), { ok: false, error: "invalid_key_handle" });
  });

  test(`m4 ${m.name}: throwing keyId, publicKey and role getters are invalid_key_handle`, async () => {
    const k = m.key();
    const base = m.handle(k, { keyId: "k", role: "issuer" });
    const boom = (): never => { throw new TypeError("getter"); };
    const keyIdThrows: Handle = { ...base, keyIdentity: () => ({ get keyId() { return boom(); }, publicKey: k.publicKey }) };
    const keyThrows: Handle = { ...base, keyIdentity: () => ({ keyId: "k", get publicKey() { return boom(); } }) };
    const roleThrows: Handle = { ...base, signingIdentity: () => ({ get role() { return boom(); }, keyId: "k", publicKey: k.publicKey }) };
    const signingKeyThrows: Handle = { ...base, signingIdentity: () => ({ role: "issuer", keyId: "k", get publicKey() { return boom(); } }) };
    assert.deepEqual(await settle(() => m.signAnchor(keyIdThrows)), { ok: false, error: "invalid_key_handle" });
    assert.deepEqual(await settle(() => m.signAnchor(keyThrows)), { ok: false, error: "invalid_key_handle" });
    assert.deepEqual(await settle(() => m.signGrant(grantInput("AAAA"), roleThrows)), { ok: false, error: "invalid_key_handle" });
    assert.deepEqual(await settle(() => m.signGrant(grantInput("AAAA"), signingKeyThrows)), { ok: false, error: "invalid_key_handle" });
  });

  test(`m4 ${m.name}: a Proxy-wrapped key from publicKey(), keyIdentity() or signingIdentity() is invalid_key_handle`, async () => {
    const k = m.key();
    const proxy = new Proxy(new Uint8Array(k.publicKey), {});
    const base = m.handle(k, { keyId: "k", role: "issuer" });
    const viaPublicKey: Handle = { ...base, publicKey: () => proxy };
    const viaIdentity: Handle = { ...base, keyIdentity: () => ({ keyId: "k", publicKey: proxy }) };
    const viaSigning: Handle = { ...base, signingIdentity: () => ({ role: "issuer", keyId: "k", publicKey: proxy }) };
    assert.deepEqual(await settle(() => m.signReport(report(new Uint8Array(10)), viaPublicKey, opts)), { ok: false, error: "invalid_key_handle" });
    assert.deepEqual(await settle(() => m.signAnchor(viaIdentity)), { ok: false, error: "invalid_key_handle" });
    assert.deepEqual(await settle(() => m.signGrant(grantInput("AAAA"), viaSigning)), { ok: false, error: "invalid_key_handle" });
  });

  test(`m5 ${m.name}: an onEvent listener that throws never escapes; the call returns its result`, async () => {
    const { issuer, holder, grant } = await fixture(m);
    const onEvent = () => { throw new Error("listener"); };
    const r = await settle(() => m.signReport(report(grant), m.handle(holder, { keyId: "holder-key" }), { ...opts, onEvent }));
    assert.equal(typeof r === "object" && r.ok, true, JSON.stringify(r));
    if (typeof r === "object" && r.ok) assert.equal(m.check(r.value!.grant, r.value!.proof, issuer.publicKey), true);
    assert.deepEqual(await settle(() => m.signReport({} as never, m.handle(holder, { keyId: "h" }), { onEvent })), { ok: false, error: "invalid_report" });
    const anchored = await settle(() => m.signAnchor(m.handle(holder, { keyId: "h" }), { onEvent }));
    assert.equal(typeof anchored === "object" && anchored.ok, true, JSON.stringify(anchored));
  });
}

test("m6: operations: [null] (and other malformed operation entries) give the same closed error on v1, v2 and v3", async () => {
  for (const operations of [[null], [{ name: "transfer", selectors: null }], [{ name: "transfer", selectors: [null] }]]) {
    const codes: unknown[] = [];
    for (const m of MAJORS) {
      const r = await settle(() => m.signGrant(grantInput("AAAA", operations), m.handle(m.key(), { keyId: "k", role: "issuer" })));
      codes.push(typeof r === "object" ? r.error : r);
    }
    assert.deepEqual(codes, ["producer_error", "producer_error", "producer_error"], JSON.stringify(operations));
  }
});
