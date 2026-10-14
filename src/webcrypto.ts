// WebCrypto key handles (signer 0.6.0): build the signer's existing KeyHandle (Ed25519, majors 1 and 2
// and the sibling profiles) and Es256KeyHandle (major 3) from a caller-owned WebCrypto key pair whose
// private key is non-extractable.
//
// The library never generates, imports, wraps, stores or exports a private key, and keeps no key bytes
// but the public key's raw export (on Deno, a Proxy that passes a private key off as the public one can
// make that export return private bytes; the factory zeroes its copy and refuses the Proxy). The
// factory reads public facts about the pair through the CryptoKey.prototype getters (captured when this
// module loads), exports the PUBLIC key in raw form, checks it, and proves the pair
// matches with one probe signature. The handle signs through the captured SubtleCrypto sign with the
// caller's private CryptoKey, held only in the handle's closure, and only over the JWS signing-input shape.
//
// This is the only file in src/ that may reach crypto.subtle (eslint.config.js), and only for two
// operations, through the methods captured at module load: sign, and exportKey with the literal "raw".
//
// What the checks are, and are not:
//   - The extractable refusal is a policy guard against an accidental pairing, not a defense against the
//     key's own holder. The getter read keeps a shadowed or faked property from defeating it by accident;
//     a determined caller can still defeat it on some engines (a Proxy over the key on Deno).
//   - Non-extractable is a browser property. On Node and Bun, code in the same process can export a
//     non-extractable private key through node:crypto's KeyObject.from(); Deno refuses.
//   - Whoever holds the handle can sign with the key. sign() accepts only the JWS signing-input shape
//     (base64url "." base64url), so the handle cannot sign arbitrary bytes, but it signs any JWS input.
//   - Everything the factory relies on from the environment is captured when this module loads:
//     crypto.subtle, SubtleCrypto.prototype.sign and exportKey, the CryptoKey getters, structuredClone
//     and Reflect.apply. A page that patches them later changes nothing here.
import {
  acceptablePublicKey,
  base64urlEncode,
  es256VerifyStrict,
  thumbprint,
  torsionFree,
  utf8Str,
  verifyStrict,
} from "@bounded-authority-protocol/verifier";
import type { Es256KeyHandle } from "./apiV3.js";
import { normalizeLowS } from "./es256.js";
import { err, ok, ownValue, type KeyHandle, type KeyRole, type SignerResult } from "./handle.js";
import { ecThumbprint, isOnCurveP256 } from "./v3.js";

// --- public types: structural only (no DOM or Node global type in any public declaration) ---

/** The public facts of a WebCrypto CryptoKey, structurally. A DOM CryptoKey and Node's webcrypto.CryptoKey both match. */
export interface WebCryptoKeyLike {
  readonly type: string;
  readonly extractable: boolean;
  readonly algorithm: { readonly name: string };
  readonly usages: readonly string[];
}

/** A WebCrypto key pair, structurally. A DOM CryptoKeyPair and Node's webcrypto.CryptoKeyPair both match. */
export interface WebCryptoKeyPairLike {
  readonly privateKey: WebCryptoKeyLike;
  readonly publicKey: WebCryptoKeyLike;
}

export interface WebCryptoHandleOptions {
  /** Enables keyIdentity() and signingIdentity(): anchors, key transitions and grants need it. */
  readonly keyId?: string;
  /** "holder" (the default) or "issuer". Only an issuer handle can sign a grant (the C1 gate). */
  readonly role?: KeyRole;
}

// --- internal ---

/** The two suites: Ed25519 (majors 1 and 2, the sibling profiles) and ES256 (major 3). */
export type Suite = "Ed25519" | "ES256";

type Getter = (this: unknown) => unknown;
interface CryptoKeyGetters {
  readonly type: Getter;
  readonly extractable: Getter;
  readonly algorithm: Getter;
}

// Captured when this module loads, so a page that replaces them later changes nothing: Reflect.apply,
// structuredClone, the CryptoKey.prototype getters, crypto.subtle and SubtleCrypto.prototype.sign and
// exportKey. The WebCrypto ones are absent outside a secure context.
const reflectApply = Reflect.apply;
const CLONE: ((value: unknown) => unknown) | undefined =
  typeof globalThis.structuredClone === "function" ? globalThis.structuredClone : undefined;

type Method = (...args: unknown[]) => unknown;

// The first own function along the prototype chain that `lookup` finds (WebIDL operations live on the
// prototype); undefined if there is none.
function findMethod(target: object, lookup: (o: object) => unknown): Method | undefined {
  for (let o: object | null = target; o !== null; o = Object.getPrototypeOf(o) as object | null) {
    const value = lookup(o);
    if (typeof value === "function") return value as Method;
  }
  return undefined;
}

const SUBTLE_TARGET: object | undefined = (() => {
  try {
    const target: unknown = (globalThis as unknown as { crypto?: { subtle?: unknown } }).crypto?.subtle;
    return target === null || typeof target !== "object" ? undefined : target;
  } catch {
    return undefined;
  }
})();
const SUBTLE_SIGN = SUBTLE_TARGET && findMethod(SUBTLE_TARGET, (o) => Object.getOwnPropertyDescriptor(o, "sign")?.value);
const SUBTLE_EXPORT_KEY = SUBTLE_TARGET && findMethod(SUBTLE_TARGET, (o) => Object.getOwnPropertyDescriptor(o, "exportKey")?.value);

/** The captured SubtleCrypto: present only when crypto.subtle and both methods were found at load. */
interface Subtle {
  readonly target: object;
}
const SUBTLE: Subtle | undefined =
  SUBTLE_TARGET !== undefined && SUBTLE_SIGN !== undefined && SUBTLE_EXPORT_KEY !== undefined ? Object.freeze({ target: SUBTLE_TARGET }) : undefined;

// The only two WebCrypto operations, through the captured methods: a signature with the caller's
// private key, and the raw export of the PUBLIC key.
const subtleSign = (subtle: Subtle, algorithm: object, key: unknown, data: Uint8Array): Promise<ArrayBuffer> =>
  reflectApply(SUBTLE_SIGN as Method, subtle.target, [algorithm, key, data]) as Promise<ArrayBuffer>;
const exportRaw = (subtle: Subtle, key: unknown): Promise<ArrayBuffer> =>
  reflectApply(SUBTLE_EXPORT_KEY as Method, subtle.target, ["raw", key]) as Promise<ArrayBuffer>;
const GETTERS: CryptoKeyGetters | undefined = (() => {
  try {
    const ctor: unknown = (globalThis as unknown as { CryptoKey?: unknown }).CryptoKey;
    if (typeof ctor !== "function") return undefined;
    const prototype = (ctor as { readonly prototype: object }).prototype;
    const getter = (name: string): Getter => {
      const get = Object.getOwnPropertyDescriptor(prototype, name)?.get;
      if (typeof get !== "function") throw new TypeError("CryptoKey getter missing");
      return get as Getter;
    };
    return Object.freeze({ type: getter("type"), extractable: getter("extractable"), algorithm: getter("algorithm") });
  } catch {
    return undefined;
  }
})();

// A brand-checked read: the engine's getter returns the key's internal slot, or throws for anything that
// is not a CryptoKey (a plain object, an object whose prototype is CryptoKey.prototype, and on most
// engines a Proxy). A throw is a refusal.
const read = (getter: Getter, key: unknown): unknown => reflectApply(getter, key, []);

const signAlgorithm = (suite: Suite) => (suite === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" });

function algorithmMatches(suite: Suite, algorithm: unknown): boolean {
  if (algorithm === null || typeof algorithm !== "object") return false;
  const { name, namedCurve } = algorithm as { name?: unknown; namedCurve?: unknown };
  return suite === "Ed25519" ? name === "Ed25519" : name === "ECDSA" && namedCurve === "P-256";
}

interface Options {
  readonly keyId: string | undefined;
  readonly role: KeyRole;
}

// Own data properties only (F1): an inherited keyId or role, including one on a polluted
// Object.prototype, is never read.
function readOptions(opts: unknown): Options | undefined {
  if (opts === undefined) return { keyId: undefined, role: "holder" };
  if (opts === null || typeof opts !== "object") return undefined;
  const keyId = ownValue(opts, "keyId");
  const role = ownValue(opts, "role");
  if (keyId !== undefined && (typeof keyId !== "string" || keyId.length === 0)) return undefined;
  if (role !== undefined && role !== "holder" && role !== "issuer") return undefined;
  return { keyId: keyId as string | undefined, role: (role as KeyRole | undefined) ?? "holder" };
}

// The fixed probe message. Its zero byte means it can never be a JWS signing input, so the probe
// signature can never be a signature over a protocol object (and handle.sign() refuses this shape).
const PROBE = Uint8Array.from("bounded-authority-protocol signer: WebCrypto key-pair probe\u0000", (c) => c.charCodeAt(0));

/** A key snapshot: the raw public key and its RFC 7638 thumbprint, captured once per handle. */
export interface KeySnapshot {
  readonly publicKey: Uint8Array;
  readonly thumbprint: string;
}

/**
 * The admission step (internal; tested directly): given the raw public-key bytes and the caller's real
 * private CryptoKey, check the bytes (Ed25519: 32 bytes, acceptablePublicKey, torsionFree; P-256: the
 * 65-byte uncompressed point on the curve), then sign the fixed probe message once with the private key
 * and verify it strictly against those bytes (verifyStrict; normalizeLowS then es256VerifyStrict). A
 * mismatched pair, a relabeled algorithm (X25519 as Ed25519, P-384 as P-256) or a key that cannot sign
 * fails here. Never throws: any failure is undefined.
 */
export async function admitKeyPair(suite: Suite, raw: Uint8Array, privateKey: unknown): Promise<KeySnapshot | undefined> {
  try {
    const subtle = SUBTLE;
    if (subtle === undefined) return undefined;
    const key = new Uint8Array(raw);
    if (suite === "Ed25519") {
      if (key.length !== 32 || !acceptablePublicKey(key) || !torsionFree(key)) return undefined;
    } else if (key.length !== 65 || key[0] !== 0x04 || !isOnCurveP256(key.subarray(1, 33), key.subarray(33))) {
      return undefined;
    }
    const signature = new Uint8Array(await subtleSign(subtle, signAlgorithm(suite), privateKey, PROBE.slice()));
    if (signature.length !== 64) return undefined;
    const matches = suite === "Ed25519" ? verifyStrict(PROBE, signature, key) : es256VerifyStrict(PROBE, normalizeLowS(signature), key);
    if (!matches) return undefined;
    const print = suite === "Ed25519" ? thumbprint({ kty: "OKP", crv: "Ed25519", x: utf8Str(base64urlEncode(key)) }) : ecThumbprint(key);
    return Object.freeze({ publicKey: key, thumbprint: print });
  } catch {
    return undefined;
  }
}

// base64url alphabet: A-Z a-z 0-9 - _
const isBase64urlByte = (b: number): boolean =>
  (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b === 0x2d || b === 0x5f;

/** A private copy of the message if it has the JWS signing-input shape ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$; throws otherwise. */
function jwsSigningInput(message: unknown): Uint8Array {
  if (!(message instanceof Uint8Array)) throw new TypeError("sign: the message must be a Uint8Array");
  const bytes = new Uint8Array(message); // checked and signed are the same bytes
  let dot = -1;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (b === 0x2e && dot === -1) dot = i;
    else if (!isBase64urlByte(b)) throw new TypeError("sign: the message is not a JWS signing input");
  }
  if (dot <= 0 || dot === bytes.length - 1) throw new TypeError("sign: the message is not a JWS signing input");
  return bytes;
}

function buildHandle(suite: Suite, subtle: Subtle, privateKey: unknown, snapshot: KeySnapshot, options: Options): KeyHandle & Es256KeyHandle {
  const publicKey = (): Uint8Array => snapshot.publicKey.slice();
  const { keyId, role } = options;
  const identity = keyId === undefined ? {} : {
    keyIdentity: () => ({ keyId, publicKey: publicKey() }),
    signingIdentity: () => ({ role, keyId, publicKey: publicKey() }),
  };
  return Object.freeze({
    // Ed25519: the 64-byte signature. ES256: WebCrypto's raw IEEE P1363 r || s, unchanged (high-S
    // included); the shared v3 tail normalizes it, exactly as for a caller-written handle.
    sign: async (message: Uint8Array): Promise<Uint8Array> =>
      new Uint8Array(await subtleSign(subtle, signAlgorithm(suite), privateKey, jwsSigningInput(message))),
    publicKey,
    thumbprint: (): string => snapshot.thumbprint,
    ...identity,
  });
}

async function keyHandle(suite: Suite, pair: unknown, opts: unknown): Promise<SignerResult<KeyHandle & Es256KeyHandle>> {
  let raw: Uint8Array | undefined;
  try {
    // 1. Runtime gate. Outside a secure context there is no crypto.subtle and no CryptoKey; nothing the
    //    caller passed is read before this passes.
    const subtle = SUBTLE;
    if (subtle === undefined || GETTERS === undefined || CLONE === undefined) return err("invalid_key_handle");
    // 2. Options.
    const options = readOptions(opts);
    if (options === undefined) return err("invalid_key_handle");
    // 3. Each key is read from the pair exactly once, from an own data property; every fact about it
    //    comes from the brand-checked getters.
    if (pair === null || typeof pair !== "object") return err("invalid_key_handle");
    const privateKey = ownValue(pair, "privateKey");
    const publicKey = ownValue(pair, "publicKey");
    // 4. Key types.
    if (read(GETTERS.type, privateKey) !== "private" || read(GETTERS.type, publicKey) !== "public") return err("invalid_key_handle");
    // 5. Extractable refusal (always; there is no option to allow an extractable private key).
    if (read(GETTERS.extractable, privateKey) !== false) return err("invalid_key_handle");
    // 6. Algorithm and curve, on both keys.
    if (!algorithmMatches(suite, read(GETTERS.algorithm, privateKey)) || !algorithmMatches(suite, read(GETTERS.algorithm, publicKey))) {
      return err("invalid_key_handle");
    }
    // 6b. Both keys must be structured-cloneable, as a real CryptoKey is (F2). A Proxy never is (the clone
    //     throws DataCloneError), which also refuses a Proxy that lies to the getters on engines whose
    //     internal slots it can reach (Deno). The clones are discarded. Each clone follows the checks that
    //     make it safe: WebKit on Linux (27.2) imports a raw P-256 point with a prefix other than 0x04 and
    //     then terminates the page when structuredClone serializes that key (it serializes a public EC key
    //     through its raw export). So the private key is cloned only once its getters say it is a private
    //     key, and the public key only after its own raw export succeeds (7b), where that export throws a
    //     catchable OperationError instead.
    CLONE(privateKey);
    // 7. The public key from its raw export (public keys are always exportable), copied: Deno (2.5.6)
    //    returns the key's own internal buffer, so writing to the returned bytes would corrupt the
    //    caller's key. Only the copy is ever written (zeroed in finally).
    raw = new Uint8Array(await exportRaw(subtle, publicKey)).slice();
    // 7b. The public key's clone (6b).
    CLONE(publicKey);
    // 8. Acceptability and the probe signature; 9. the snapshot (its own copy of the bytes).
    const snapshot = await admitKeyPair(suite, raw, privateKey);
    if (snapshot === undefined) return err("invalid_key_handle");
    return ok(buildHandle(suite, subtle, privateKey, snapshot, options));
  } catch {
    return err("invalid_key_handle");
  } finally {
    raw?.fill(0);
  }
}

/**
 * Build an Ed25519 KeyHandle (contract-majors 1 and 2, the sibling profiles) from a WebCrypto key pair
 * whose private key is non-extractable. Resolves { ok: false, error: "invalid_key_handle" } for anything
 * else; never throws and never rejects.
 */
export function ed25519KeyHandle(pair: WebCryptoKeyPairLike, opts?: WebCryptoHandleOptions): Promise<SignerResult<KeyHandle>> {
  return keyHandle("Ed25519", pair, opts);
}

/**
 * Build an ES256 Es256KeyHandle (contract-major 3) from a WebCrypto ECDSA P-256 key pair whose private
 * key is non-extractable. Resolves { ok: false, error: "invalid_key_handle" } for anything else; never
 * throws and never rejects.
 */
export function es256KeyHandle(pair: WebCryptoKeyPairLike, opts?: WebCryptoHandleOptions): Promise<SignerResult<Es256KeyHandle>> {
  return keyHandle("ES256", pair, opts);
}
