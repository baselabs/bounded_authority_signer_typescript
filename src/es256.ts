// The ES256 signing tail — the v3 mirror of sign.ts's shared tail: sign via
// the handle → NORMALIZE to low-S → VERIFY STRICTLY against the resolved public
// key (the wrong-key guard) → assemble the compact. Pure: normalization is
// BigInt arithmetic and the verify is the verifier package's synchronous
// es256VerifyStrict, so this module needs no Node API and runs unchanged in
// browsers, Deno, Bun and workers. The private key never enters here.
//
// Low-S is load-bearing (spec/bap-v3.md §3.2; REQ3-SIGNING-low-s): a backend
// emits high-`s` about half the time, and for any valid `(r, s)` the
// counterpart `(r, n − s)` also verifies — so an emitted high-`s` signature
// would be malleable. The normalizer is ONE conditional subtraction
// (`s ← n − s` when high) with no modular inverse, deliberately implementable
// per the owner's 2026-09-20 decision. The emitted `s` satisfies
// `0 < s ≤ (n−1)/2` always (`n` is odd, so the ceiling is `(n−1)/2`).
//
// The post-sign verify is strict: es256VerifyStrict refuses `s > (n−1)/2`, so a
// missed or broken normalization fails closed as signing_failed instead of
// emitting a malleable signature.
import { es256VerifyStrict, type Bounds } from "@bounded-authority-protocol/verifier";
import { assembleCompact, RAW_SIGNATURE_BYTES, type V3SigningInput } from "./v3.js";
import { err, ok, type SignerResult } from "./handle.js";

// The P-256 group order n (SEC 2) and the low-S ceiling (n−1)/2 (n is odd).
export const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
export const P256_HALF_ORDER = (P256_ORDER - 1n) / 2n;

function bigEndianToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const byte of bytes) v = (v << 8n) | BigInt(byte);
  return v;
}

function bigIntToFixedWidth(v: bigint, width: number): Uint8Array {
  const out = new Uint8Array(width);
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Low-S normalization (REQ3-SIGNING-low-s): given a 64-byte raw `r || s`
 * signature, returns the encoding with `s` in `0 < s ≤ (n−1)/2` — replacing a
 * high `s` with `n − s` (equally valid for the same key and message), leaving
 * a low `s` untouched. It first asserts `0 < r < n` and `0 < s < n` and throws
 * otherwise (the signing tail maps the throw to signing_failed). Pure: no
 * crypto, no allocation beyond the output copy.
 */
export function normalizeLowS(signature: Uint8Array): Uint8Array {
  if (signature.length !== RAW_SIGNATURE_BYTES)
    throw new Error("normalizeLowS: signature must be 64 bytes");
  const r = bigEndianToBigInt(signature.subarray(0, 32));
  const s = bigEndianToBigInt(signature.subarray(32));
  if (r <= 0n || r >= P256_ORDER) throw new Error("normalizeLowS: r outside (0, n)");
  if (s <= 0n || s >= P256_ORDER) throw new Error("normalizeLowS: s outside (0, n)");
  if (s <= P256_HALF_ORDER) return signature;
  const out = new Uint8Array(signature);
  out.set(bigIntToFixedWidth(P256_ORDER - s, 32), 32);
  return out;
}

/**
 * The strict post-sign check: verify a 64-byte raw `r || s` ES256 signature
 * over the message under the 65-byte raw public key with the verifier
 * package's es256VerifyStrict (key on the curve, `0 < r < n`,
 * `0 < s ≤ (n−1)/2`, then the backend verify). A high-`s` signature, a
 * rejection, or an exception returns false, never throws
 * (REQ3-SIGNING-backend-reject).
 */
export function es256Verifies(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return es256VerifyStrict(message, signature, publicKey);
  } catch {
    return false;
  }
}

/** Sign via the handle callback; a fault, reject, or wrong width yields undefined. */
export async function signViaEs256Handle(
  sign: (message: Uint8Array) => Uint8Array | Promise<Uint8Array>,
  message: Uint8Array,
): Promise<Uint8Array | undefined> {
  try {
    const signature = await sign(message);
    return signature instanceof Uint8Array && signature.length === RAW_SIGNATURE_BYTES ? signature : undefined;
  } catch {
    return undefined;
  }
}

// The ASCII "protected.payload" pre-signature message (RFC 7515, the exact
// JWS signing input).
function signingInputMessage(input: V3SigningInput): Uint8Array {
  const parts = [input.protectedSegment, input.payloadSegment];
  const len = parts.reduce((n, p) => n + p.length + 1, 0);
  const out = new Uint8Array(len - 1);
  let i = 0;
  for (const [idx, p] of parts.entries()) {
    out.set(p, i);
    i += p.length;
    if (idx === 0) out[i++] = 46; // "."
  }
  return out;
}

/**
 * The v3 shared signing tail: sign → normalize to low-S → strict verify
 * (wrong-key guard and low-S check) → assemble. The wrong-key guard is the same RA1 discipline as the v1
 * tail: a handle whose `sign()` used a different key fails loudly as
 * `signing_failed`, never a silent false-success deferred to the verifier.
 */
export async function signV3AndAssemble(
  sign: (message: Uint8Array) => Uint8Array | Promise<Uint8Array>,
  signingInput: V3SigningInput,
  publicKey: Uint8Array,
  bounds: Bounds | undefined,
): Promise<SignerResult<Uint8Array>> {
  const message = signingInputMessage(signingInput);
  const signed = await signViaEs256Handle(sign, message);
  if (signed === undefined) return err("signing_failed");
  let signature: Uint8Array;
  try {
    signature = normalizeLowS(signed);
  } catch {
    return err("signing_failed"); // r or s outside (0, n)
  }
  if (!es256Verifies(message, signature, publicKey)) return err("signing_failed");
  const compact = assembleCompact(signingInput, signature, bounds);
  return compact.ok ? ok(compact.value) : err("producer_error");
}
