// The shared signing tail — the port of BARA's universal companion primitive:
// sign via the handle → VERIFY the signature against the resolved public key →
// assemble through the verifier package. Every object this library signs flows
// through here.
//
// The wrong-key guard is the RA1 cross-vendor finding: a signature that does
// not verify against the resolved public key is signing_failed, never a silent
// false-success deferred to the verifier downstream.
import {
  assembleCompact,
  assembleLocalLoopbackHttpCompact,
  v2,
  verifyStrict,
  type Bounds,
  type Result,
  type SigningInput,
} from "@bounded-authority-protocol/verifier";
import { err, ok, type SignerResult } from "./handle.js";

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

// The self-verify is the verifier package's strict Ed25519 check (rule S1: canonical A and R, no
// small-order A or R, S < L, then the cofactorless equation), never a lenient backend verify — a
// backend that accepts R = identity, S = 0 under a weak key must not pass here.
export function signatureVerifies(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return verifyStrict(message, signature, publicKey);
  } catch {
    return false;
  }
}

export type Assembler = (input: SigningInput, signature: Uint8Array, bounds?: Bounds) => Result<Uint8Array>;

const standard: Assembler = (input, signature, bounds) => assembleCompact(input, signature, bounds);
const loopback: Assembler = (input, signature, bounds) => assembleLocalLoopbackHttpCompact(input, signature, bounds);
// Contract-major 2: the verifier's v2.assembleCompact (v:2 payloads, BAP2-* separators, same Ed25519 suite).
const major2: Assembler = (input, signature, bounds) => v2.assembleCompact(input, signature, bounds);

export const assemblers = { standard, loopback, v2: major2 } as const;

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
