// The shared signing tail — the port of BARA's universal companion primitive:
// sign via the handle → VERIFY the signature against the resolved public key →
// assemble through the verifier package. Every object this library signs flows
// through here.
//
// The wrong-key guard is the RA1 cross-vendor finding: a signature that does
// not verify against the resolved public key is signing_failed, never a silent
// false-success deferred to the verifier downstream.
import { createPublicKey, verify as edVerify, type KeyObject } from "node:crypto";
import {
  assembleCompact,
  assembleLocalLoopbackHttpCompact,
  type Bounds,
  type Result,
  type SigningInput,
} from "@bounded-authority-protocol/verifier";
import { err, ok, type SignerResult } from "./handle.js";

// RFC 8037 Ed25519 public JWK from the raw 32-byte key (x = base64url of the key).
const ed25519 = (raw: Uint8Array): KeyObject =>
  createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" });

export async function signViaHandle(
  sign: (message: Uint8Array) => Uint8Array | Promise<Uint8Array>,
  message: Uint8Array,
): Promise<Uint8Array | undefined> {
  try {
    const signature = await sign(message);
    return signature instanceof Uint8Array && signature.length === 64 ? signature : undefined;
  } catch {
    return undefined;
  }
}

export function signatureVerifies(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return edVerify(null, Buffer.from(message), ed25519(publicKey), Buffer.from(signature));
  } catch {
    return false;
  }
}

export type Assembler = (input: SigningInput, signature: Uint8Array, bounds?: Bounds) => Result<Uint8Array>;

const standard: Assembler = (input, signature, bounds) => assembleCompact(input, signature, bounds);
const loopback: Assembler = (input, signature, bounds) => assembleLocalLoopbackHttpCompact(input, signature, bounds);

export const assemblers = { standard, loopback } as const;

export async function signAndAssemble(
  sign: (message: Uint8Array) => Uint8Array | Promise<Uint8Array>,
  signingInput: SigningInput,
  publicKey: Uint8Array,
  bounds: Bounds | undefined,
  assembler: Assembler,
): Promise<SignerResult<Uint8Array>> {
  const signature = await signViaHandle(sign, signingInputMessage(signingInput));
  if (signature === undefined) return err("signing_failed");
  if (!signatureVerifies(signingInputMessage(signingInput), signature, publicKey)) return err("signing_failed");
  const compact = assembler(signingInput, signature, bounds);
  return compact.ok ? ok(compact.value) : err("producer_error");
}

// The ASCII "protected.payload" pre-signature message.
function signingInputMessage(input: SigningInput): Uint8Array {
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
