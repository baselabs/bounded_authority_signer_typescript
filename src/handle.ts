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

const isUint8 = (v: unknown): v is Uint8Array => v instanceof Uint8Array;

/** A handle callback fault (throw, reject, bad shape) maps to the closed error, never escapes. */
async function call<T>(fn: () => T | Promise<T>): Promise<T | undefined> {
  try {
    return await fn();
  } catch {
    return undefined;
  }
}

const isEd25519Key = (v: unknown): v is Uint8Array => isUint8(v) && v.length === 32;

export async function resolvePublicKey(handle: KeyHandle): Promise<Uint8Array | undefined> {
  const key = await call(() => handle.publicKey());
  return isEd25519Key(key) ? key : undefined;
}

export async function resolveKeyIdentity(handle: KeyHandle): Promise<AtomicKeyIdentity | undefined> {
  const snap = await call(() => handle.keyIdentity?.());
  if (snap === undefined) return undefined;
  if (typeof snap.keyId !== "string" || snap.keyId.length === 0) return undefined;
  if (!isEd25519Key(snap.publicKey)) return undefined;
  return snap;
}

/** The C1 gate: grants require an issuer-role identity resolved atomically. */
export async function resolveIssuerIdentity(handle: KeyHandle): Promise<AtomicKeyIdentity | undefined> {
  const snap = await call(() => handle.signingIdentity?.());
  if (snap === undefined || snap === null) return undefined;
  if (snap.role !== "issuer") return undefined;
  if (typeof snap.keyId !== "string" || snap.keyId.length === 0) return undefined;
  if (!isEd25519Key(snap.publicKey)) return undefined;
  return { keyId: snap.keyId, publicKey: snap.publicKey };
}
