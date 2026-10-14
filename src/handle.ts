// The key-handle contract — the port of BARA's {module(), term()} callbacks
// (charter §6 invariant 1: the private key NEVER enters this library).
//
// The caller supplies an object whose methods reach their own custody (an HSM
// client, a KMS, or an in-process key in tests). Every method may return a
// Promise; the library awaits, so remote custodians are first-class.
//
//   - sign(message) -> Uint8Array(64)          required, every operation
//   - publicKey()    -> Uint8Array(32)         required, every operation
//   - thumbprint()   -> string (RFC 7638 b64)  required (caller-side self-check)
//   - keyIdentity()  -> {keyId, publicKey}     required by anchor + transition:
//                                              kid AND public key as ONE atomic
//                                              snapshot, so a stateful handle
//                                              cannot split them across a
//                                              rotation race
//   - signingIdentity() -> {role, keyId, publicKey}
//                                              required by grant signing: role
//                                              AND kid AND public key as ONE
//                                              atomic snapshot. A holder-role
//                                              handle can never sign a grant —
//                                              the C1 gate.

import { acceptablePublicKey } from "@bounded-authority-protocol/verifier";

export type KeyRole = "issuer" | "holder";

export interface AtomicKeyIdentity {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}

export interface AtomicSigningIdentity extends AtomicKeyIdentity {
  readonly role: KeyRole;
}

export interface KeyHandle {
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;
  publicKey(): Uint8Array | Promise<Uint8Array>;
  thumbprint(): string | Promise<string>;
  keyIdentity?(): AtomicKeyIdentity | Promise<AtomicKeyIdentity>;
  signingIdentity?(): AtomicSigningIdentity | Promise<AtomicSigningIdentity>;
}

export type SignerErrorCode =
  | "invalid_report"
  | "invalid_anchor"
  | "invalid_grant"
  | "invalid_transition"
  | "invalid_key_handle"
  | "signing_failed"
  | "producer_error";

export type SignerResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: SignerErrorCode };

export const ok = <T>(value: T): SignerResult<T> => ({ ok: true, value });
export const err = <T = never>(error: SignerErrorCode): SignerResult<T> => ({ ok: false, error });

// --- resolution: every read of a handle happens inside one try, and what comes back is a COPY ---
//
// A handle is caller code. Any of its methods or getters may throw, return null, return a Proxy, or keep
// a reference to the array it returned and rewrite it later. So each resolver reads the snapshot's
// fields once, inside a try, validates them there, and returns its own fresh object with a private
// copy of the key: a later rewrite of the handle's array cannot change the key the library composes
// with and checks against. Snapshot fields are read from OWN data properties only (ownValue), so an
// inherited or polluted role, key id or key never counts. Any fault is undefined, which the signers map
// to invalid_key_handle.

/** A key check over the library's own copy (width, and for Ed25519 the verifier's acceptability). */
export type KeyCheck = (key: Uint8Array) => boolean;

// A handle's Ed25519 public key must be 32 bytes AND acceptable to the verifier: canonical, not one of
// the eight small-order points (identity included), and on the curve. A weak key is refused here, at
// resolution, before sign() is ever called — a handle that reports one is an invalid_key_handle.
export const ed25519Key: KeyCheck = (key) => key.length === 32 && acceptablePublicKey(key);

/** Copy a handle-supplied key; throws for a Proxy or other non-typed-array (callers are inside a try). */
function copyKey(value: unknown, check: KeyCheck): Uint8Array | undefined {
  if (!(value instanceof Uint8Array)) return undefined;
  const copy = new Uint8Array(value);
  return check(copy) ? copy : undefined;
}

const isKeyId = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/**
 * An OWN data property's value, or undefined: never an inherited property (a polluted Object.prototype
 * cannot supply a role or a key id) and never a getter's result.
 */
export const ownValue = (object: object, key: string): unknown => Object.getOwnPropertyDescriptor(object, key)?.value;

export async function resolveKeyWith(read: () => unknown, check: KeyCheck): Promise<Uint8Array | undefined> {
  try {
    return copyKey(await read(), check);
  } catch {
    return undefined;
  }
}

export async function resolveIdentityWith(read: () => unknown, check: KeyCheck): Promise<AtomicKeyIdentity | undefined> {
  try {
    const snap: unknown = await read();
    if (snap === null || typeof snap !== "object") return undefined;
    const keyId = ownValue(snap, "keyId");
    const publicKey = ownValue(snap, "publicKey");
    if (!isKeyId(keyId)) return undefined;
    const key = copyKey(publicKey, check);
    return key === undefined ? undefined : { keyId, publicKey: key };
  } catch {
    return undefined;
  }
}

/** The C1 gate: grants require an issuer-role identity resolved atomically. */
export async function resolveIssuerWith(read: () => unknown, check: KeyCheck): Promise<AtomicKeyIdentity | undefined> {
  try {
    const snap: unknown = await read();
    if (snap === null || typeof snap !== "object") return undefined;
    const role = ownValue(snap, "role");
    const keyId = ownValue(snap, "keyId");
    const publicKey = ownValue(snap, "publicKey");
    if (role !== "issuer" || !isKeyId(keyId)) return undefined;
    const key = copyKey(publicKey, check);
    return key === undefined ? undefined : { keyId, publicKey: key };
  } catch {
    return undefined;
  }
}

export function resolvePublicKey(handle: KeyHandle): Promise<Uint8Array | undefined> {
  return resolveKeyWith(() => handle.publicKey(), ed25519Key);
}

export function resolveKeyIdentity(handle: KeyHandle): Promise<AtomicKeyIdentity | undefined> {
  return resolveIdentityWith(() => handle.keyIdentity?.(), ed25519Key);
}

export function resolveIssuerIdentity(handle: KeyHandle): Promise<AtomicKeyIdentity | undefined> {
  return resolveIssuerWith(() => handle.signingIdentity?.(), ed25519Key);
}

// --- events: a listener is caller code too; its exceptions are swallowed, never change a result ---

export type Phase = "start" | "stop" | "error";

export function emitter<K extends string>(opts: unknown, kind: K): (phase: Phase) => void {
  return (phase) => {
    try {
      (opts as { onEvent?: (event: { kind: K; phase: Phase }) => void } | undefined)?.onEvent?.({ kind, phase });
    } catch {
      // A throwing listener is ignored: the signing result is the same with or without it.
    }
  };
}
