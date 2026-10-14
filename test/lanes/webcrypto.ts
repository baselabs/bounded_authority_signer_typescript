// The WebCrypto key-handle battery (signer 0.6.0, design §12.8), run in every lane: Node 22 and 24 (the
// unit suite and the runtime lanes), Deno, Bun, and real Chromium, Firefox and WebKit pages under the
// strict CSP. Every key is a REAL engine key generated in the lane (test/lanes/webcrypto-keys.ts); no
// mocks. Each check compares verdicts through the verifier package, never signature bytes across
// engines. The battery returns its checks (each must be true in every lane), an engine capability row
// (recorded, never skipped), and the observed outcomes whose expected value differs per lane (T4b), which
// the harness asserts lane by lane.
//
// Rows (design §12.8, with the judged revisions of October 14):
//   T1 accept; T2 sign then verify on v1, v2 and v3 over 64 DISTINCT inputs; T3 extractable refused;
//   T4 shadowed or string-lying extractable; T4b a symbol-flipping Proxy (observed per lane); T5 not a
//   CryptoKey, never a rejection; T6 wrong types, algorithms and relabeled algorithms; T7 weak Ed25519
//   public keys; T8 the internal admission step over mutated raw bytes; T9 mismatched pairs refused at
//   the factory; T10 roles and identity; T12 no key exposure; R13 the JWS-shape restriction on sign() and
//   the getters captured at module load; R10 a key from another realm (browsers pass one in).
import {
  acceptablePublicKey,
  base64urlDecode,
  base64urlEncode,
  checkEnvelope,
  checkLocalLoopbackHttpEnvelope,
  publicKeyThumbprintRaw,
  strUtf8,
  thumbprint,
  torsionFree,
  utf8Str,
  verifyGrant,
  verifyHistoricalAnchor,
  verifyKeyTransition,
  v2,
  v3,
  type Tagged,
} from "@bounded-authority-protocol/verifier";
import {
  ed25519KeyHandle,
  es256KeyHandle,
  signAnchor,
  signGrant,
  signKeyTransition,
  signLocalLoopbackReport,
  signReport,
  signV2Anchor,
  signV2Grant,
  signV2KeyTransition,
  signV2Report,
  signV3Anchor,
  signV3Grant,
  signV3KeyTransition,
  signV3Report,
  type Es256KeyHandle,
  type KeyHandle,
  type WebCryptoKeyPairLike,
} from "../../src/index.js";
import { admitKeyPair } from "../../src/webcrypto.js";
import { P256_HALF_ORDER, P256_ORDER } from "../../src/es256.js";
import * as K from "./webcrypto-keys.js";

export const DISTINCT_INPUTS = 64;

const ISS = "https://issuer.example.test";
const AUD = "https://resource.example.test";
const TARGET = `${AUD}/invoke`;
const INV = "550e8400-e29b-41d4-a716-446655440000";
const args = (): Tagged => ({ t: "object", v: new Map([["amount", { t: "int", v: 5000 }]]) });
const report = (grantCompact: Uint8Array, invocationId = INV) => ({ grantCompact, operation: "transfer", method: "POST", targetUri: TARGET, invocationId, castArguments: args() });
const grantInput = (holderThumbprint: string, selectors: never[]) => ({
  issuer: ISS, grantId: "urn:example:grant:wc", audiences: [AUD], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint, operations: [{ name: "transfer", selectors }],
});
const ALL = [{ kind: "all" }] as never[];
const LTE = [{ kind: "lte", path: ["amount"], value: { t: "int", v: 10_000 } }] as never[];
const expected = (publicKey: Uint8Array, invocationId = INV) => ({
  trustedIssuer: { keyId: "issuer-key", publicKey }, issuer: ISS, audience: AUD, method: "POST", targetUri: TARGET,
  invocationId, operation: "transfer", castArguments: args(), evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300,
  nonce: { kind: "not_required" as const },
});
const opts = (proofId = "urn:example:proof:wc") => ({ issuedAt: 1500, proofId });
const histKey = (keyId: string, publicKey: Uint8Array, validFrom = 0) => ({ keyId, publicKey, validFrom, validBefore: null });
const LOOPBACK = "http://127.0.0.1:8080/invoke";

const b64 = (bytes: Uint8Array): string => utf8Str(base64urlEncode(bytes));
const ascii = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0));
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const bigOf = (bytes: Uint8Array): bigint => bytes.reduce((v, x) => (v << 8n) | BigInt(x), 0n);
const signatureOf = (compact: Uint8Array): Uint8Array => {
  const text = new TextDecoder().decode(compact);
  return base64urlDecode(strUtf8(text.slice(text.lastIndexOf(".") + 1)));
};

/** "ok", "error:<code>", or "rejected:<name>" (a factory must never reach the last one). */
async function outcome(run: () => Promise<{ ok: boolean; error?: string }>): Promise<string> {
  try {
    const r = await run();
    return r.ok ? "ok" : `error:${r.error}`;
  } catch (e) {
    return `rejected:${e instanceof Error ? e.name : typeof e}`;
  }
}
const refused = "error:invalid_key_handle";

async function settles(promise: Promise<unknown>): Promise<"resolved" | "rejected"> {
  try {
    await promise;
    return "resolved";
  } catch {
    return "rejected";
  }
}

// The brand check the tests use to recognize a CryptoKey (never the library's captured copy).
function isCryptoKey(value: unknown): boolean {
  try {
    const ctor = (globalThis as unknown as { CryptoKey: { prototype: object } }).CryptoKey;
    Reflect.apply(Object.getOwnPropertyDescriptor(ctor.prototype, "type")!.get!, value, []);
    return true;
  } catch {
    return false;
  }
}

function algorithmObject(key: unknown): Record<string, unknown> {
  const ctor = (globalThis as unknown as { CryptoKey: { prototype: object } }).CryptoKey;
  return Reflect.apply(Object.getOwnPropertyDescriptor(ctor.prototype, "algorithm")!.get!, key, []) as Record<string, unknown>;
}

// A sign() wrapper that records the handle's raw output and counts calls (the handle itself is frozen).
function recording<H extends KeyHandle | Es256KeyHandle>(handle: H, raw: Uint8Array[] = [], calls = { count: 0 }): H {
  return { ...handle, sign: async (m: Uint8Array) => { calls.count += 1; const s = await handle.sign(m); raw.push(new Uint8Array(s)); return s; } };
}

export interface WebCryptoLaneOptions {
  /** Browsers only: a pair generated by a same-origin iframe's crypto.subtle (another realm). */
  readonly foreignRealmPairs?: () => Promise<{ ed: WebCryptoKeyPairLike; ec: WebCryptoKeyPairLike }>;
  /** Browsers only: pairs generated in a dedicated worker and posted to the page (structured clone). */
  readonly workerPairs?: () => Promise<{ ed: WebCryptoKeyPairLike; ec: WebCryptoKeyPairLike }>;
}

export interface WebCryptoLaneReport {
  readonly checks: Record<string, boolean>;
  readonly capability: Record<string, unknown>;
  /** Outcomes whose expected value is set per lane by the harness (design §12.3, revision R1). */
  readonly observed: { readonly proxySymbolFlip: string };
}

export async function runWebCryptoLane(options: WebCryptoLaneOptions = {}): Promise<WebCryptoLaneReport> {
  const checks: Record<string, boolean> = {};
  const capability: Record<string, unknown> = {};
  K.generateRetries.count = 0;
  const s = K.subtle();

  // ---- capability row ----
  capability.ed25519Generate = await settles(K.edPair()) === "resolved";
  capability.ecdsaP256Generate = await settles(K.ecPair()) === "resolved";

  // ---- T1 accept ----
  const edReal = await K.edPair();
  const ecReal = await K.ecPair();
  const edRaw = await K.rawPublicKey(edReal);
  const ecRaw = await K.rawPublicKey(ecReal);
  let t0 = performance.now();
  const ed = await ed25519KeyHandle(edReal);
  capability.ed25519FactoryMs = Math.round((performance.now() - t0) * 100) / 100;
  t0 = performance.now();
  const ec = await es256KeyHandle(ecReal);
  capability.es256FactoryMs = Math.round((performance.now() - t0) * 100) / 100;
  checks["T1 the factories leave the caller's keys intact (a fresh raw export equals the copy taken before)"] =
    equal(await K.rawPublicKey(edReal), edRaw) && equal(await K.rawPublicKey(ecReal), ecRaw);
  checks["T1 ed25519KeyHandle: a real non-extractable Ed25519 pair -> ok"] = ed.ok;
  checks["T1 es256KeyHandle: a real non-extractable P-256 pair -> ok"] = ec.ok;
  if (ed.ok) {
    const pk = await ed.value.publicKey();
    checks["T1 ed25519: publicKey() equals the raw export"] = equal(pk, edRaw);
    checks["T1 ed25519: thumbprint() equals the verifier's thumbprint of the raw key"] =
      (await ed.value.thumbprint()) === thumbprint({ kty: "OKP", crv: "Ed25519", x: b64(edRaw) });
    pk.fill(0);
    checks["T1 ed25519: publicKey() returns a fresh copy each call"] = equal(await ed.value.publicKey(), edRaw);
  }
  if (ec.ok) {
    checks["T1 es256: publicKey() equals the raw export"] = equal(await ec.value.publicKey(), ecRaw);
    checks["T1 es256: thumbprint() equals the verifier's v3 thumbprint of the raw key"] =
      (await ec.value.thumbprint()) === v3.thumbprint({ crv: "P-256", kty: "EC", x: b64(ecRaw.subarray(1, 33)), y: b64(ecRaw.subarray(33)) });
  }
  capability.ed25519RawWidth = edRaw.length;
  capability.p256RawWidth = ecRaw.length;

  // ---- T2 sign then verify (v1, v2, v3) ----
  {
    const issuerPair = await K.edPair();
    const issuerRaw = await K.rawPublicKey(issuerPair);
    const issuer = await ed25519KeyHandle(issuerPair, { keyId: "issuer-key", role: "issuer" });
    const holder = await ed25519KeyHandle(await K.edPair());
    let v1 = false;
    let v2ok = false;
    if (issuer.ok && holder.ok) {
      const holderPrint = await holder.value.thumbprint();
      const g = await signGrant(grantInput(holderPrint, ALL), issuer.value);
      const e = g.ok ? await signReport(report(g.value.grant), holder.value, opts()) : g;
      v1 = e.ok && checkEnvelope(e.value.grant, e.value.proof, expected(issuerRaw)).ok;
      const g2 = await signV2Grant(grantInput(holderPrint, LTE), issuer.value);
      const e2 = g2.ok ? await signV2Report(report(g2.value.grant), holder.value, opts()) : g2;
      v2ok = e2.ok && v2.checkEnvelope(e2.value.grant, e2.value.proof, expected(issuerRaw)).ok;
    }
    checks["T2 v1: signGrant (issuer handle) + signReport (holder handle) -> checkEnvelope accepts"] = v1;
    checks["T2 v2: signV2Grant + signV2Report -> v2.checkEnvelope accepts"] = v2ok;

    const ecIssuerPair = await K.ecPair();
    const ecIssuerRaw = await K.rawPublicKey(ecIssuerPair);
    const ecIssuer = await es256KeyHandle(ecIssuerPair, { keyId: "issuer-key", role: "issuer" });
    const ecHolder = await es256KeyHandle(await K.ecPair());
    let allVerify = ecIssuer.ok && ecHolder.ok;
    let allLow = allVerify;
    let normalizedExactly = allVerify;
    let highS = 0;
    const distinct = new Set<string>();
    if (ecIssuer.ok && ecHolder.ok) {
      const g = await signV3Grant(grantInput(await ecHolder.value.thumbprint(), ALL), ecIssuer.value);
      allVerify &&= g.ok;
      for (let i = 0; g.ok && i < DISTINCT_INPUTS; i++) {
        const raw: Uint8Array[] = [];
        const invocationId = `550e8400-e29b-41d4-a716-${(446655440000 + i).toString().padStart(12, "0")}`;
        const e = await signV3Report(report(g.value.grant, invocationId), recording(ecHolder.value, raw), opts(`urn:example:proof:wc:${i}`));
        if (!e.ok || raw.length !== 1) { allVerify = false; continue; }
        allVerify &&= v3.checkEnvelope(e.value.grant, e.value.proof, expected(ecIssuerRaw, invocationId)).ok;
        const emitted = signatureOf(e.value.proof);
        distinct.add(b64(emitted));
        const sEmitted = bigOf(emitted.subarray(32));
        const sRaw = bigOf(raw[0]!.subarray(32));
        allLow &&= sEmitted > 0n && sEmitted <= P256_HALF_ORDER && equal(emitted.subarray(0, 32), raw[0]!.subarray(0, 32));
        if (sRaw > P256_HALF_ORDER) {
          highS += 1;
          normalizedExactly &&= sEmitted === P256_ORDER - sRaw;
        } else {
          normalizedExactly &&= equal(emitted, raw[0]!);
        }
      }
    }
    checks[`T2 v3: ${DISTINCT_INPUTS} signV3Report over distinct inputs -> v3.checkEnvelope accepts each`] = allVerify && distinct.size === DISTINCT_INPUTS;
    checks["T2 v3: the handle's raw output includes high-S, and every emitted s is in (0, (n-1)/2] with r untouched"] = highS > 0 && allLow;
    checks["T2 v3: a high raw s is emitted as n - s, a low one unchanged"] = normalizedExactly;
    capability.es256HighSOfDistinctInputs = `${highS}/${DISTINCT_INPUTS}`;

    // Whether the engine's ECDSA and Ed25519 are deterministic (same key, same message, same bytes).
    if (ecHolder.ok && ed.ok) {
      const m = ascii("eyJhIjoxfQ.eyJiIjoyfQ");
      capability.ecdsaDeterministic = equal(await ecHolder.value.sign(m), await ecHolder.value.sign(m));
      capability.ed25519Deterministic = equal(await ed.value.sign(m), await ed.value.sign(m));
      capability.es256SignWidth = (await ecHolder.value.sign(m)).length;
      capability.ed25519SignWidth = (await ed.value.sign(m)).length;
    }
  }

  // ---- T3 extractable refused (always; no option allows it) ----
  checks["T3 ed25519KeyHandle: a real extractable pair -> invalid_key_handle"] = await outcome(async () => ed25519KeyHandle(await K.edPair(true))) === refused;
  checks["T3 es256KeyHandle: a real extractable pair -> invalid_key_handle"] = await outcome(async () => es256KeyHandle(await K.ecPair(true))) === refused;

  // ---- T4 shadowed / string-lying extractable ----
  {
    const ex = await K.edPair(true);
    Object.defineProperty(ex.privateKey, "extractable", { value: false });
    checks["T4 an extractable key with an own extractable: false -> invalid_key_handle"] =
      ex.privateKey.extractable === false && await outcome(() => ed25519KeyHandle(ex)) === refused;
    const ex2 = await K.ecPair(true);
    const lying = new Proxy(ex2.privateKey, { get: (target, key) => (key === "extractable" ? false : Reflect.get(target, key)) });
    checks["T4 a Proxy lying about the string key extractable -> invalid_key_handle"] =
      await outcome(() => es256KeyHandle({ privateKey: lying, publicKey: ex2.publicKey })) === refused;
  }

  // ---- T4 (F2) a Proxy around a real key, even a non-extractable one, is refused (it is not structured-cloneable) ----
  {
    const nx = await K.edPair(false);
    checks["T4 (F2) an empty Proxy over a real non-extractable private key -> invalid_key_handle"] =
      await outcome(() => ed25519KeyHandle({ privateKey: new Proxy(nx.privateKey, {}), publicKey: nx.publicKey })) === refused;
    checks["T4 (F2) an empty Proxy over a real public key -> invalid_key_handle"] =
      await outcome(() => ed25519KeyHandle({ privateKey: nx.privateKey, publicKey: new Proxy(nx.publicKey, {}) })) === refused;
  }

  // ---- T4b a Proxy that flips every symbol-keyed true to false (attacks JS-implemented internal slots) ----
  let proxySymbolFlip: string;
  {
    const ex = await K.edPair(true);
    const flip = new Proxy(ex.privateKey, {
      get(target, key) {
        const value: unknown = Reflect.get(target, key);
        return typeof key === "symbol" && value === true ? false : value;
      },
    });
    proxySymbolFlip = await outcome(() => ed25519KeyHandle({ privateKey: flip, publicKey: ex.publicKey }));
    checks["T4b the symbol-flip Proxy never makes the factory reject"] = !proxySymbolFlip.startsWith("rejected:");
  }

  // ---- T5 not a CryptoKey: refused, never a rejection ----
  {
    const fake = (type: string, name: string) => ({ type, extractable: false, algorithm: { name }, usages: type === "private" ? ["sign"] : ["verify"] });
    const ctor = (globalThis as unknown as { CryptoKey: { prototype: object } }).CryptoKey;
    const protoFake = (type: string, name: string) => Object.setPrototypeOf(fake(type, name), ctor.prototype) as WebCryptoKeyPairLike["privateKey"];
    const throwing = { get privateKey(): never { throw new Error("getter"); }, get publicKey(): never { throw new Error("getter"); } };
    const cases: Record<string, () => Promise<{ ok: boolean; error?: string }>> = {
      "plain objects (Ed25519 shape)": () => ed25519KeyHandle({ privateKey: fake("private", "Ed25519"), publicKey: fake("public", "Ed25519") }),
      "plain objects (P-256 shape)": () => es256KeyHandle({ privateKey: { ...fake("private", "ECDSA"), algorithm: { name: "ECDSA", namedCurve: "P-256" } } as never, publicKey: { ...fake("public", "ECDSA"), algorithm: { name: "ECDSA", namedCurve: "P-256" } } as never }),
      "objects whose prototype is CryptoKey.prototype": () => ed25519KeyHandle({ privateKey: protoFake("private", "Ed25519"), publicKey: protoFake("public", "Ed25519") }),
      "Object.create(CryptoKey.prototype)": () => ed25519KeyHandle({ privateKey: Object.create(ctor.prototype) as never, publicKey: Object.create(ctor.prototype) as never }),
      "a real private key with a plain public object": () => ed25519KeyHandle({ privateKey: edReal.privateKey, publicKey: fake("public", "Ed25519") }),
      "pair null": () => ed25519KeyHandle(null as never),
      "pair undefined": () => es256KeyHandle(undefined as never),
      "pair a number": () => ed25519KeyHandle(42 as never),
      "pair with throwing getters": () => es256KeyHandle(throwing as never),
      "options null": () => ed25519KeyHandle(edReal, null as never),
      "options a string": () => ed25519KeyHandle(edReal, "issuer" as never),
      "keyId empty": () => ed25519KeyHandle(edReal, { keyId: "" }),
      "keyId not a string": () => es256KeyHandle(ecReal, { keyId: 7 as never }),
      "role not holder or issuer": () => ed25519KeyHandle(edReal, { keyId: "k", role: "admin" as never }),
    };
    for (const [name, run] of Object.entries(cases)) checks[`T5 ${name} -> invalid_key_handle, never a rejection`] = await outcome(run) === refused;

    // F1: only OWN data properties of the options are read; inherited ones (and a polluted
    // Object.prototype) never reach the handle.
    const inherited = await ed25519KeyHandle(edReal, Object.create({ keyId: "proto-k", role: "issuer" }) as never);
    checks["T5 (F1) Object.create({ keyId, role: \"issuer\" }) options are ignored: a handle with no identity"] =
      inherited.ok && inherited.value.keyIdentity === undefined && inherited.value.signingIdentity === undefined;
    const ownKeyId = await ed25519KeyHandle(edReal, Object.assign(Object.create({ role: "issuer" }) as object, { keyId: "k" }) as never);
    checks["T5 (F1) an own keyId with an inherited role \"issuer\" -> a holder handle that cannot sign a grant"] = ownKeyId.ok &&
      (await ownKeyId.value.signingIdentity?.())?.role === "holder" &&
      await outcome(() => signGrant(grantInput("AAAA", ALL), ownKeyId.value)) === refused;
    const proto = Object.prototype as Record<string, unknown>;
    let polluted = "not run";
    try {
      Object.defineProperty(proto, "role", { value: "issuer", configurable: true, writable: true, enumerable: false });
      Object.defineProperty(proto, "keyId", { value: "polluted", configurable: true, writable: true, enumerable: false });
      const withId = await ed25519KeyHandle(edReal, { keyId: "k" });
      const without = await ed25519KeyHandle(edReal, {});
      const noOpts = await es256KeyHandle(ecReal);
      polluted = JSON.stringify([
        withId.ok ? (await withId.value.signingIdentity?.())?.role : "refused",
        withId.ok ? await outcome(() => signGrant(grantInput("AAAA", ALL), withId.value)) : "refused",
        without.ok ? typeof without.value.keyIdentity : "refused",
        noOpts.ok ? typeof noOpts.value.signingIdentity : "refused",
      ]);
    } finally {
      delete proto.role;
      delete proto.keyId;
    }
    checks["T5 (F1) a polluted Object.prototype.role and .keyId do not reach the handle"] =
      polluted === JSON.stringify(["holder", refused, "undefined", "undefined"]);
  }

  // ---- T6 wrong types, algorithms, curves; relabeled algorithms ----
  {
    const p384 = await K.generate(K.P384, false);
    const mixedEd = { privateKey: edReal.privateKey, publicKey: ecReal.publicKey };
    const mixedEc = { privateKey: ecReal.privateKey, publicKey: edReal.publicKey };
    const cases: Record<string, () => Promise<{ ok: boolean; error?: string }>> = {
      "swapped private and public (Ed25519)": () => ed25519KeyHandle({ privateKey: edReal.publicKey, publicKey: edReal.privateKey }),
      "swapped private and public (P-256)": () => es256KeyHandle({ privateKey: ecReal.publicKey, publicKey: ecReal.privateKey }),
      "both keys the private key": () => ed25519KeyHandle({ privateKey: edReal.privateKey, publicKey: edReal.privateKey }),
      "an Ed25519 pair to es256KeyHandle": () => es256KeyHandle(edReal),
      "a P-256 pair to ed25519KeyHandle": () => ed25519KeyHandle(ecReal),
      "a P-384 pair to es256KeyHandle": () => es256KeyHandle(p384),
      "an Ed25519 private key with a P-256 public key": () => ed25519KeyHandle(mixedEd),
      "a P-256 private key with an Ed25519 public key": () => es256KeyHandle(mixedEc),
    };
    for (const [name, run] of Object.entries(cases)) checks[`T6 ${name} -> invalid_key_handle`] = await outcome(run) === refused;

    // R2: a relabeled algorithm. Where an engine returns the same mutable algorithm object from the getter,
    // a caller can rename X25519 to Ed25519 (or P-384 to P-256). The X25519 row retries until the exported
    // bytes pass acceptablePublicKey and torsionFree, so only the probe signature can refuse it.
    let sticks = false;
    let tries = 0;
    let x25519 = "not run";
    for (; tries < 256; tries++) { // about 1 in 16 X25519 keys qualifies; 256 tries miss with probability below 1e-7
      const x = await K.generate(K.X25519, false, ["deriveBits"]);
      algorithmObject(x.privateKey).name = "Ed25519";
      algorithmObject(x.publicKey).name = "Ed25519";
      sticks = algorithmObject(x.privateKey).name === "Ed25519";
      const raw = await K.rawPublicKey(x);
      if (sticks && !(acceptablePublicKey(raw) && torsionFree(raw))) continue;
      x25519 = await outcome(() => ed25519KeyHandle(x));
      break;
    }
    capability.algorithmRelabelSticks = sticks;
    capability.x25519RelabelTries = tries + 1;
    checks["T6 (R2) an X25519 pair relabeled Ed25519 (exported bytes acceptable) -> invalid_key_handle"] = x25519 === refused;
    const p = await K.generate(K.P384, false);
    algorithmObject(p.privateKey).namedCurve = "P-256";
    algorithmObject(p.publicKey).namedCurve = "P-256";
    checks["T6 (R2) a P-384 pair relabeled P-256 -> invalid_key_handle"] = await outcome(() => es256KeyHandle(p)) === refused;
  }

  // ---- T7 weak Ed25519 public keys paired with a real private key ----
  {
    const imports: Record<string, string> = {};
    for (const [name, h] of Object.entries(K.WEAK_ED25519)) {
      const pub = await K.importPublic(K.hex(h), K.ED25519);
      imports[name] = pub === undefined ? "refused" : "accepted";
      checks[`T7 a real private key with the public ${name} key -> invalid_key_handle`] =
        pub === undefined || await outcome(() => ed25519KeyHandle({ privateKey: edReal.privateKey, publicKey: pub })) === refused;
    }
    capability.weakEd25519PublicImport = imports;
    const torsioned = K.hex(K.WEAK_ED25519["torsioned (honest point plus a small-order point)"]!);
    checks["T7 vector check: the torsioned key passes acceptablePublicKey and fails torsionFree"] = acceptablePublicKey(torsioned) && !torsionFree(torsioned);
    checks["T7 vector check: the y = p key fails acceptablePublicKey"] = !acceptablePublicKey(K.hex(K.WEAK_ED25519["non-canonical (y = p)"]!));
  }

  // ---- T8 the admission step (raw public bytes plus the real private key), over mutated bytes ----
  {
    checks["T8 admitKeyPair: the unmutated P-256 export with its own private key -> admitted"] = (await admitKeyPair("ES256", ecRaw, ecReal.privateKey)) !== undefined;
    for (const [name, bytes] of Object.entries(K.p256Mutations(ecRaw))) {
      checks[`T8 admitKeyPair (P-256): ${name} -> refused`] = (await admitKeyPair("ES256", bytes, ecReal.privateKey)) === undefined;
    }
    checks["T8 admitKeyPair: the unmutated Ed25519 export with its own private key -> admitted"] = (await admitKeyPair("Ed25519", edRaw, edReal.privateKey)) !== undefined;
    for (const [name, bytes] of Object.entries(K.ed25519Mutations(edRaw))) {
      checks[`T8 admitKeyPair (Ed25519): ${name} -> refused`] = (await admitKeyPair("Ed25519", bytes, edReal.privateKey)) === undefined;
    }
    // The lane records whether the engine imports off-curve P-256 bytes at all; where it does, the factory
    // refuses the imported key (its raw export fails, or the admission step refuses the bytes).
    const imports: Record<string, string> = {};
    for (const [name, bytes] of Object.entries(K.p256Mutations(ecRaw))) {
      if (bytes.length !== 65) continue;
      const pub = await K.importPublic(bytes, K.P256);
      imports[name] = pub === undefined ? "refused" : "accepted";
      checks[`T8 factory: a real private key with an imported ${name} public key -> invalid_key_handle`] =
        pub === undefined || await outcome(() => es256KeyHandle({ privateKey: ecReal.privateKey, publicKey: pub })) === refused;
      // The same imported key in the privateKey slot (WebKit on Linux terminates the page if the factory
      // structured-clones it before the type check refuses it).
      checks[`T8 factory: an imported ${name} public key passed as the private key -> invalid_key_handle (es256 and ed25519 factories)`] =
        pub === undefined || (await outcome(() => es256KeyHandle({ privateKey: pub, publicKey: ecReal.publicKey })) === refused &&
          await outcome(() => ed25519KeyHandle({ privateKey: pub, publicKey: edReal.publicKey })) === refused);
    }
    capability.p256MutatedPublicImport = imports;
  }

  // ---- T9 mismatched pairs are refused at the factory (the probe signature, revision R2) ----
  {
    const otherEd = await K.edPair();
    const otherEc = await K.ecPair();
    checks["T9 Ed25519: private key of pair A with public key of pair B -> invalid_key_handle"] =
      await outcome(() => ed25519KeyHandle({ privateKey: edReal.privateKey, publicKey: otherEd.publicKey })) === refused;
    checks["T9 P-256: private key of pair A with public key of pair B -> invalid_key_handle"] =
      await outcome(() => es256KeyHandle({ privateKey: ecReal.privateKey, publicKey: otherEc.publicKey })) === refused;
    checks["T9 admitKeyPair: pair B's raw public key with pair A's private key -> refused"] =
      (await admitKeyPair("Ed25519", await K.rawPublicKey(otherEd), edReal.privateKey)) === undefined &&
      (await admitKeyPair("ES256", await K.rawPublicKey(otherEc), ecReal.privateKey)) === undefined;
  }

  // ---- T10 roles and identity ----
  {
    const chainPair = await K.edPair();
    const chainRaw = await K.rawPublicKey(chainPair);
    const holderWithId = await ed25519KeyHandle(await K.edPair(), { keyId: "holder-key" });
    const noId = await ed25519KeyHandle(await K.edPair());
    const chain = await ed25519KeyHandle(chainPair, { keyId: "chain-key" });
    const issuerPair = await K.edPair();
    const issuer = await ed25519KeyHandle(issuerPair, { keyId: "issuer-key", role: "issuer" });
    const calls = { count: 0 };
    if (holderWithId.ok && noId.ok && chain.ok && issuer.ok) {
      checks["T10 a holder handle (default role) cannot sign a grant -> invalid_key_handle, sign() never called"] =
        await outcome(() => signGrant(grantInput("AAAA", ALL), recording(holderWithId.value, [], calls))) === refused && calls.count === 0;
      checks["T10 a handle without keyId has no keyIdentity/signingIdentity"] =
        noId.value.keyIdentity === undefined && noId.value.signingIdentity === undefined;
      checks["T10 signAnchor without keyId -> invalid_key_handle"] =
        await outcome(() => signAnchor({ anchorId: "urn:example:anchor:wc", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) }, noId.value, { anchoredAt: 1200 })) === refused;
      const a = await signAnchor({ anchorId: "urn:example:anchor:wc", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) }, chain.value, { anchoredAt: 1200 });
      checks["T10 signAnchor with keyId -> verifyHistoricalAnchor accepts"] = a.ok && verifyHistoricalAnchor(a.value.anchor, histKey("chain-key", chainRaw), {
        anchorId: "urn:example:anchor:wc", chainId: "urn:example:chain", keyId: "chain-key", sequence: 0, anchoredAt: 1200,
        chainHash: new Uint8Array(32), keyFingerprint: publicKeyThumbprintRaw(chainRaw),
      }).ok;
      const g = await signGrant(grantInput(await noId.value.thumbprint(), ALL), issuer.value);
      checks["T10 an issuer handle with keyId signs a grant -> verifyGrant accepts"] = g.ok &&
        verifyGrant(g.value.grant, { keyId: "issuer-key", publicKey: await K.rawPublicKey(issuerPair) }, { issuer: ISS, audience: AUD, evaluationTime: 1500, clockSkew: 60 }).ok;
    } else {
      checks["T10 handles built"] = false;
    }
    const ecHolder = await es256KeyHandle(await K.ecPair(), { keyId: "holder-key" });
    const ecChainPair = await K.ecPair();
    const ecChainRaw = await K.rawPublicKey(ecChainPair);
    const ecChain = await es256KeyHandle(ecChainPair, { keyId: "chain-key" });
    if (ecHolder.ok && ecChain.ok) {
      const ecCalls = { count: 0 };
      checks["T10 v3: a holder handle cannot sign a grant -> invalid_key_handle, sign() never called"] =
        await outcome(() => signV3Grant(grantInput("AAAA", ALL), recording(ecHolder.value, [], ecCalls))) === refused && ecCalls.count === 0;
      const a = await signV3Anchor({ anchorId: "urn:example:anchor:wc3", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) }, ecChain.value, { anchoredAt: 1200 });
      checks["T10 v3: signV3Anchor with keyId -> v3.verifyHistoricalAnchor accepts"] = a.ok && v3.verifyHistoricalAnchor(a.value.anchor, histKey("chain-key", ecChainRaw), {
        anchorId: "urn:example:anchor:wc3", chainId: "urn:example:chain", keyId: "chain-key", sequence: 0, anchoredAt: 1200,
        chainHash: new Uint8Array(32), keyFingerprint: base64urlDecode(strUtf8(await ecChain.value.thumbprint())),
      }).ok;
    } else {
      checks["T10 v3 handles built"] = false;
    }
  }

  // ---- T12 no key exposure; the handle is frozen (revision R9) ----
  {
    const withId = await ed25519KeyHandle(edReal, { keyId: "k", role: "issuer" });
    const ecWithId = await es256KeyHandle(ecReal, { keyId: "k" });
    let exposed = false;
    const seen = new Set<unknown>();
    const walk = (value: unknown): void => {
      if (value === null || (typeof value !== "object" && typeof value !== "function") || seen.has(value)) return;
      seen.add(value);
      if (isCryptoKey(value)) exposed = true;
      for (const key of Reflect.ownKeys(value as object)) {
        const d = Object.getOwnPropertyDescriptor(value, key);
        if (d && "value" in d) walk(d.value);
      }
    };
    if (ed.ok && withId.ok && ec.ok && ecWithId.ok) {
      for (const h of [ed.value, withId.value, ec.value, ecWithId.value]) {
        walk(h);
        walk(await h.publicKey());
        walk(await h.keyIdentity?.());
        walk(await h.signingIdentity?.());
      }
      checks["T12 a handle's own keys are exactly its methods"] =
        JSON.stringify(Reflect.ownKeys(ed.value).map(String).sort()) === JSON.stringify(["publicKey", "sign", "thumbprint"]) &&
        JSON.stringify(Reflect.ownKeys(withId.value).map(String).sort()) === JSON.stringify(["keyIdentity", "publicKey", "sign", "signingIdentity", "thumbprint"]);
      checks["T12 a deep walk of the handles' own properties finds no CryptoKey"] = !exposed && seen.size > 0;
      checks["T12 JSON.stringify(handle) carries no key data"] = JSON.stringify(withId.value) === "{}" && JSON.stringify(ecWithId.value) === "{}";
      checks["T12 (R9) the handle is frozen"] = [ed.value, withId.value, ec.value, ecWithId.value].every((h) => Object.isFrozen(h));
      const role = (await withId.value.signingIdentity?.())?.role;
      checks["T12 signingIdentity() carries the role option"] = role === "issuer" && (await ecWithId.value.signingIdentity?.())?.role === "holder";
    } else {
      checks["T12 handles built"] = false;
    }
  }

  // ---- R13 sign() accepts only the JWS signing-input shape; getters are captured at module load ----
  {
    if (ed.ok && ec.ok) {
      const nonJws: Record<string, unknown> = {
        "a zero byte (the probe shape)": ascii("eyJh.eyJi\u0000"),
        "no dot": ascii("eyJhbGciOiJFZERTQSJ9"),
        "two dots": ascii("a.b.c"),
        "leading dot": ascii(".b"),
        "trailing dot": ascii("a."),
        "a space": ascii("a b.c"),
        "padding '='": ascii("YQ==.Yg"),
        "base64 '+' and '/'": ascii("a+/.b"),
        "empty": new Uint8Array(0),
        "a string, not bytes": "a.b",
      };
      for (const [name, message] of Object.entries(nonJws)) {
        checks[`R13 handle.sign rejects ${name}`] =
          await settles(Promise.resolve().then(() => ed.value.sign(message as Uint8Array))) === "rejected" &&
          await settles(Promise.resolve().then(() => ec.value.sign(message as Uint8Array))) === "rejected";
      }
      const sig = await ed.value.sign(ascii("eyJhbGciOiJFZERTQSJ9.e30"));
      checks["R13 handle.sign accepts a JWS signing input"] = sig.length === 64 && (await ec.value.sign(ascii("A-_z.0-9"))).length === 64;
    } else {
      checks["R13 handles built"] = false;
    }
    // A page that replaces CryptoKey.prototype's extractable getter AFTER the library loaded does not
    // change what the factory reads. The replacement lies only for private keys: some engines (Node) read
    // the public getter inside subtle.exportKey, so a lie about the public key would make the export fail
    // and refuse the pair for the wrong reason.
    const ctor = (globalThis as unknown as { CryptoKey: { prototype: object } }).CryptoKey;
    const original = Object.getOwnPropertyDescriptor(ctor.prototype, "extractable");
    const originalType = Object.getOwnPropertyDescriptor(ctor.prototype, "type")!.get!;
    let replaced = false;
    let result = "not run";
    try {
      const truth = original!.get!;
      Object.defineProperty(ctor.prototype, "extractable", {
        configurable: true,
        enumerable: true,
        get(this: unknown) {
          return Reflect.apply(originalType, this, []) === "private" ? false : Reflect.apply(truth, this, []);
        },
      });
      replaced = true;
      const ex = await K.edPair(true);
      result = await outcome(() => ed25519KeyHandle(ex));
    } catch {
      replaced = false;
    } finally {
      if (original) Object.defineProperty(ctor.prototype, "extractable", original);
    }
    capability.cryptoKeyGetterReplaceable = replaced;
    checks["R13 a getter replaced after module load does not admit an extractable key"] = replaced && result === refused;
  }

  // ---- F3 SubtleCrypto.prototype.sign and exportKey patched after module load change nothing ----
  {
    const A = await K.edPair(false);
    const B = await K.edPair(true);
    const aRaw = await K.rawPublicKey(A);
    const proto = Object.getPrototypeOf(s) as { sign: (...a: unknown[]) => unknown; exportKey: (...a: unknown[]) => unknown };
    const signDescriptor = Object.getOwnPropertyDescriptor(proto, "sign");
    const exportDescriptor = Object.getOwnPropertyDescriptor(proto, "exportKey");
    const origSign = proto.sign;
    const origExport = proto.exportKey;
    let swapped = "not run";
    let patchedCalls = -1;
    try {
      if (!signDescriptor || !exportDescriptor) throw new Error("sign and exportKey are not own properties of the SubtleCrypto prototype");
      // P1: a page swaps A's keys for an EXTRACTABLE pair B inside sign and exportKey.
      Object.defineProperty(proto, "sign", { ...signDescriptor, value: function (this: unknown, alg: unknown, key: unknown, data: unknown) { return Reflect.apply(origSign, this, [alg, key === A.privateKey ? B.privateKey : key, data]); } });
      Object.defineProperty(proto, "exportKey", { ...exportDescriptor, value: function (this: unknown, format: unknown, key: unknown) { return Reflect.apply(origExport, this, [format, key === A.publicKey ? B.publicKey : key]); } });
      const h = await ed25519KeyHandle(A);
      swapped = h.ok ? (equal(await h.value.publicKey(), aRaw) ? "A" : "B") : h.error;
      if (signDescriptor) Object.defineProperty(proto, "sign", signDescriptor);
      if (exportDescriptor) Object.defineProperty(proto, "exportKey", exportDescriptor);
      // P1b: a sign patched AFTER construction is never called by the existing handle.
      const h2 = await ed25519KeyHandle(A);
      let calls = 0;
      Object.defineProperty(proto, "sign", { ...signDescriptor, value: function (this: unknown, ...a: unknown[]) { calls += 1; return Reflect.apply(origSign, this, a); } });
      if (h2.ok) await h2.value.sign(ascii("YQ.Yg"));
      patchedCalls = calls;
    } finally {
      if (signDescriptor) Object.defineProperty(proto, "sign", signDescriptor);
      if (exportDescriptor) Object.defineProperty(proto, "exportKey", exportDescriptor);
    }
    checks["F3 (P1) sign and exportKey patched after module load: the handle still holds A's own public key"] = swapped === "A";
    checks["F3 (P1b) a sign patched after construction is not called by the handle"] = patchedCalls === 0;
  }

  // ---- F4 the remaining signers with factory handles, each verified by the verifier ----
  {
    const issuerPair = await K.edPair();
    const issuer = await ed25519KeyHandle(issuerPair, { keyId: "issuer-key", role: "issuer" });
    const holder = await ed25519KeyHandle(await K.edPair());
    let loopback = false;
    if (issuer.ok && holder.ok) {
      const g = await signGrant(grantInput(await holder.value.thumbprint(), ALL), issuer.value);
      const lb = g.ok ? await signLocalLoopbackReport({ ...report(g.value.grant), targetUri: LOOPBACK, nonce: "n-1" }, holder.value, opts()) : g;
      loopback = lb.ok && checkLocalLoopbackHttpEnvelope(lb.value.grant, lb.value.proof, {
        ...expected(await K.rawPublicKey(issuerPair)), targetUri: LOOPBACK, nonce: { kind: "required", value: "n-1" },
      } as never).ok;
    }
    checks["F4 signLocalLoopbackReport -> checkLocalLoopbackHttpEnvelope accepts"] = loopback;

    const transition = { transitionId: "urn:example:transition:wc", chainId: "urn:example:chain", effectiveAt: 1500, nextKeyId: "chain-key-2" };
    const expectTransition = (current: Uint8Array, next: Uint8Array, currentPrint: Uint8Array, nextPrint: Uint8Array) => ({
      transitionId: transition.transitionId, chainId: transition.chainId, effectiveAt: 1500,
      currentKeyFingerprint: currentPrint, nextKeyFingerprint: nextPrint, currentKeyId: "chain-key", nextKeyId: "chain-key-2",
    });
    for (const [label, sign, verify] of [
      ["F4 signKeyTransition -> verifyKeyTransition accepts", signKeyTransition, verifyKeyTransition],
      ["F4 signV2KeyTransition -> v2.verifyKeyTransition accepts", signV2KeyTransition, v2.verifyKeyTransition],
    ] as const) {
      const cp = await K.edPair();
      const np = await K.edPair();
      const cr = await K.rawPublicKey(cp);
      const nr = await K.rawPublicKey(np);
      const chain = await ed25519KeyHandle(cp, { keyId: "chain-key" });
      const t = chain.ok ? await sign({ ...transition, nextPublicKey: nr }, chain.value) : chain;
      checks[label] = t.ok && verify(t.value.keyTransition, histKey("chain-key", cr), histKey("chain-key-2", nr, 1500),
        expectTransition(cr, nr, publicKeyThumbprintRaw(cr), publicKeyThumbprintRaw(nr))).ok;
    }
    {
      const cp = await K.edPair();
      const cr = await K.rawPublicKey(cp);
      const chain = await ed25519KeyHandle(cp, { keyId: "chain-key" });
      const a = chain.ok ? await signV2Anchor({ anchorId: "urn:example:anchor:wc2", chainId: "urn:example:chain", sequence: 0, chainHash: new Uint8Array(32) }, chain.value, { anchoredAt: 1200 }) : chain;
      checks["F4 signV2Anchor -> v2.verifyHistoricalAnchor accepts"] = a.ok && v2.verifyHistoricalAnchor(a.value.anchor, histKey("chain-key", cr), {
        anchorId: "urn:example:anchor:wc2", chainId: "urn:example:chain", keyId: "chain-key", sequence: 0, anchoredAt: 1200,
        chainHash: new Uint8Array(32), keyFingerprint: publicKeyThumbprintRaw(cr),
      }).ok;
    }
    {
      const cp = await K.ecPair();
      const np = await K.ecPair();
      const cr = await K.rawPublicKey(cp);
      const nr = await K.rawPublicKey(np);
      const chain = await es256KeyHandle(cp, { keyId: "chain-key" });
      const next = await es256KeyHandle(np);
      const fp = (t: string) => base64urlDecode(strUtf8(t));
      const t = chain.ok ? await signV3KeyTransition({ ...transition, nextPublicKey: nr }, chain.value) : chain;
      checks["F4 signV3KeyTransition -> v3.verifyKeyTransition accepts"] = t.ok && chain.ok && next.ok &&
        v3.verifyKeyTransition(t.value.keyTransition, histKey("chain-key", cr), histKey("chain-key-2", nr, 1500),
          expectTransition(cr, nr, fp(await chain.value.thumbprint()), fp(await next.value.thumbprint()))).ok;
    }
  }

  // ---- R10 a key from another realm (browsers: a same-origin iframe) is accepted and signs ----
  if (options.foreignRealmPairs) {
    const ctor = (globalThis as unknown as { CryptoKey: abstract new () => unknown }).CryptoKey;
    const foreign = await options.foreignRealmPairs();
    const fed = await ed25519KeyHandle(foreign.ed);
    const fec = await es256KeyHandle(foreign.ec);
    checks["R10 the iframe-realm keys fail instanceof CryptoKey in this realm (so an instanceof check would refuse them)"] =
      !(foreign.ed.privateKey instanceof ctor) && !(foreign.ec.privateKey instanceof ctor);
    checks["R10 an iframe-realm Ed25519 pair -> ok, and it signs a verifiable report"] = fed.ok && await (async () => {
      const issuerPair = await K.edPair();
      const issuer = await ed25519KeyHandle(issuerPair, { keyId: "issuer-key", role: "issuer" });
      if (!issuer.ok) return false;
      const g = await signGrant(grantInput(await fed.value.thumbprint(), ALL), issuer.value);
      const e = g.ok ? await signReport(report(g.value.grant), fed.value, opts()) : g;
      return e.ok && checkEnvelope(e.value.grant, e.value.proof, expected(await K.rawPublicKey(issuerPair))).ok;
    })();
    checks["R10 an iframe-realm P-256 pair -> ok"] = fec.ok;
  }

  // ---- R10/F9 a key generated in a dedicated worker and posted to the page is accepted and signs ----
  if (options.workerPairs) {
    const posted = await options.workerPairs();
    const wed = await ed25519KeyHandle(posted.ed);
    const wec = await es256KeyHandle(posted.ec);
    checks["R10 (F9) a worker-posted Ed25519 pair -> ok, and it signs a verifiable report"] = wed.ok && await (async () => {
      const issuerPair = await K.edPair();
      const issuer = await ed25519KeyHandle(issuerPair, { keyId: "issuer-key", role: "issuer" });
      if (!issuer.ok) return false;
      const g = await signGrant(grantInput(await wed.value.thumbprint(), ALL), issuer.value);
      const e = g.ok ? await signReport(report(g.value.grant), wed.value, opts()) : g;
      return e.ok && checkEnvelope(e.value.grant, e.value.proof, expected(await K.rawPublicKey(issuerPair))).ok;
    })();
    checks["R10 (F9) a worker-posted P-256 pair -> ok"] = wec.ok;
  }

  // ---- capability: can a private CryptoKey be structured-cloned in this engine (workers, IndexedDB)? ----
  try {
    const clone = structuredClone(edReal.privateKey);
    capability.structuredCloneKey = isCryptoKey(clone) && (await ed25519KeyHandle({ privateKey: clone, publicKey: edReal.publicKey })).ok ? "ok" : "clone not usable";
  } catch (e) {
    capability.structuredCloneKey = `threw:${e instanceof Error ? e.name : typeof e}`;
  }

  capability.generateRetries = K.generateRetries.count; // engine OperationErrors retried (K.retryOperationError)
  return { checks, capability, observed: { proxySymbolFlip } };
}
