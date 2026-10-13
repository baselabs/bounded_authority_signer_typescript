// The four contract-major-3 companion signers — the ES256-suite mirror of the
// v1 five-function surface (the local-loopback profile is contract-major-1
// bound and has no v3 form). Same structure as api.ts: validate the input →
// resolve the handle's identity atomically → compose through the v3 producers
// (src/v3.ts, the in-repo producing profile) → sign through the ES256 tail
// (src/es256.ts: sign → low-S normalize → wrong-key verify → assemble).
import type { Bounds, Tagged } from "@bounded-authority-protocol/verifier";
import type { AnchorCompact, Envelope, GrantCompact, TransitionCompact } from "./api.js";
import {
  boundaryAnchorSigningInput,
  grantSigningInput,
  keyTransitionSigningInput,
  proofSigningInput,
  type V3OperationInput,
} from "./v3.js";
import { signV3AndAssemble } from "./es256.js";
import {
  emitter,
  err,
  ok,
  resolveIdentityWith,
  resolveIssuerWith,
  resolveKeyWith,
  type AtomicSigningIdentity,
  type KeyCheck,
  type SignerResult,
} from "./handle.js";
import { defaultProofId } from "./proof-id.js";

// The ES256 key-handle contract — the same caller-owned-custody shape as the
// v1 KeyHandle, with the suite's fixed widths: sign() returns the 64-byte raw
// `r || s` (high-S permitted from the custodian — the library normalizes
// before emission), publicKey() the 65-byte uncompressed-SEC1 point, and
// thumbprint() the RFC 7638 EC thumbprint (base64url). The private key never
// enters this library.
export interface Es256KeyHandle {
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>; // 64-byte raw r || s
  publicKey(): Uint8Array | Promise<Uint8Array>;               // 65 bytes: 0x04 || x || y
  thumbprint(): string | Promise<string>;                      // RFC 7638 EC, base64url
  keyIdentity?(): { keyId: string; publicKey: Uint8Array } | Promise<{ keyId: string; publicKey: Uint8Array }>;
  signingIdentity?(): Promise<AtomicSigningIdentity> | AtomicSigningIdentity;
}

export interface V3SignerEvent {
  readonly kind: "v3_report" | "v3_anchor" | "v3_grant" | "v3_key_transition";
  readonly phase: "start" | "stop" | "error";
}

export interface V3SignOpts {
  readonly bounds?: Bounds;
  readonly issuedAt?: number;    // default: wall clock seconds
  readonly proofId?: string;     // default: crypto.randomUUID() (producer_error where it is absent)
  readonly anchoredAt?: number;  // anchor timestamp (default: wall clock seconds)
  readonly onEvent?: (event: V3SignerEvent) => void;
}

export interface V3ReportInput {
  readonly grantCompact: Uint8Array;
  readonly operation: string;
  readonly method: string;
  readonly targetUri: string;
  readonly invocationId: string;
  readonly castArguments: Tagged;
  readonly nonce?: string;
}

export interface V3AnchorInput {
  readonly anchorId: string;
  readonly chainId: string;
  readonly sequence: number;
  readonly chainHash: Uint8Array; // 32 bytes
}

export interface V3GrantInput {
  readonly issuer: string;
  readonly grantId: string;
  readonly audiences: readonly string[];
  readonly issuedAt: number;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly holderThumbprint: string; // RFC 7638 EC thumbprint, base64url
  readonly operations: readonly V3OperationInput[];
}

export interface V3TransitionInput {
  readonly transitionId: string;
  readonly chainId: string;
  readonly effectiveAt: number;
  readonly nextKeyId: string;
  readonly nextPublicKey: Uint8Array; // 65 bytes: 0x04 || x || y
}

const nowSeconds = () => Math.floor(Date.now() / 1000);
const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isU8 = (v: unknown, n?: number): v is Uint8Array => v instanceof Uint8Array && (n === undefined || v.length === n);

// --- handle resolvers: the v1 resolvers (one try, a private copy of the key, a fresh snapshot object)
// with the suite's 65-byte uncompressed-SEC1 width -----------------------------------------------

const p256Key: KeyCheck = (key) => key.length === 65;
type Es256KeyIdentity = { keyId: string; publicKey: Uint8Array };

const resolveEs256PublicKey = (handle: Es256KeyHandle): Promise<Uint8Array | undefined> => resolveKeyWith(() => handle.publicKey(), p256Key);
const resolveEs256KeyIdentity = (handle: Es256KeyHandle): Promise<Es256KeyIdentity | undefined> => resolveIdentityWith(() => handle.keyIdentity?.(), p256Key);
/** The C1 gate, ES256 form: grants require an issuer-role identity resolved atomically. */
const resolveEs256IssuerIdentity = (handle: Es256KeyHandle): Promise<Es256KeyIdentity | undefined> => resolveIssuerWith(() => handle.signingIdentity?.(), p256Key);

// --- the four signers --------------------------------------------------------

function validateReport(report: V3ReportInput): SignerResult<V3ReportInput> {
  if (!isU8(report?.grantCompact) || !isStr(report?.operation) || !isStr(report?.method) ||
      !isStr(report?.targetUri) || !isStr(report?.invocationId) || report?.castArguments === undefined) {
    return err("invalid_report");
  }
  if (report.nonce !== undefined && typeof report.nonce !== "string") return err("invalid_report");
  return ok(report);
}

export async function signV3Report(report: V3ReportInput, handle: Es256KeyHandle, opts: V3SignOpts = {}): Promise<SignerResult<Envelope>> {
  const emit = emitter(opts, "v3_report");
  emit("start");
  const validated = validateReport(report);
  if (!validated.ok) { emit("error"); return validated; }

  const holderPublicKey = await resolveEs256PublicKey(handle);
  if (holderPublicKey === undefined) { emit("error"); return err("invalid_key_handle"); }

  const proofId = defaultProofId(opts.proofId);
  if (proofId === undefined) { emit("error"); return err("producer_error"); }

  const proof = {
    holderPublicKey, proofId, method: report.method,
    targetUri: report.targetUri, issuedAt: opts.issuedAt ?? nowSeconds(),
    invocationId: report.invocationId, operation: report.operation,
    grantCompact: report.grantCompact, castArguments: report.castArguments,
    ...(report.nonce === undefined ? {} : { nonce: report.nonce }),
  };
  const produced = proofSigningInput(proof, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signV3AndAssemble((m) => handle.sign(m), produced.value, holderPublicKey, opts.bounds);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ grant: report.grantCompact, proof: assembled.value });
}

export async function signV3Anchor(input: V3AnchorInput, handle: Es256KeyHandle, opts: V3SignOpts = {}): Promise<SignerResult<AnchorCompact>> {
  const emit = emitter(opts, "v3_anchor");
  emit("start");
  if (!isStr(input?.anchorId) || !isStr(input?.chainId) || !Number.isInteger(input?.sequence) || !isU8(input?.chainHash, 32)) {
    emit("error");
    return err("invalid_anchor");
  }
  const identity = await resolveEs256KeyIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  const produced = boundaryAnchorSigningInput({
    anchorId: input.anchorId, anchoredAt: opts.anchoredAt ?? nowSeconds(), chainId: input.chainId,
    sequence: input.sequence, chainHash: input.chainHash, keyId: identity.keyId, publicKey: identity.publicKey,
  }, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signV3AndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ anchor: assembled.value });
}

export async function signV3Grant(input: V3GrantInput, handle: Es256KeyHandle, opts: V3SignOpts = {}): Promise<SignerResult<GrantCompact>> {
  const emit = emitter(opts, "v3_grant");
  emit("start");
  if (!isStr(input?.issuer) || !isStr(input?.grantId) || !Array.isArray(input?.audiences) ||
      ![input?.issuedAt, input?.notBefore, input?.expiresAt].every(Number.isInteger) ||
      !isStr(input?.holderThumbprint) || !Array.isArray(input?.operations)) {
    emit("error");
    return err("invalid_grant");
  }
  // The C1 gate (ES256 form): only an issuer-role identity (resolved
  // atomically) may sign a grant — a holder handle fails closed BEFORE
  // sign() is ever called.
  const identity = await resolveEs256IssuerIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  const produced = grantSigningInput({
    keyId: identity.keyId, issuer: input.issuer, grantId: input.grantId, audiences: [...input.audiences],
    issuedAt: input.issuedAt, notBefore: input.notBefore, expiresAt: input.expiresAt,
    holderThumbprint: input.holderThumbprint, operations: [...input.operations],
  }, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signV3AndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ grant: assembled.value });
}

export async function signV3KeyTransition(input: V3TransitionInput, handle: Es256KeyHandle, opts: V3SignOpts = {}): Promise<SignerResult<TransitionCompact>> {
  const emit = emitter(opts, "v3_key_transition");
  emit("start");
  if (!isStr(input?.transitionId) || !isStr(input?.chainId) || !Number.isInteger(input?.effectiveAt) ||
      !isStr(input?.nextKeyId) || !isU8(input?.nextPublicKey, 65)) {
    emit("error");
    return err("invalid_transition");
  }
  const identity = await resolveEs256KeyIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  const produced = keyTransitionSigningInput({
    transitionId: input.transitionId, chainId: input.chainId, effectiveAt: input.effectiveAt,
    currentKeyId: identity.keyId, currentPublicKey: identity.publicKey,
    nextKeyId: input.nextKeyId, nextPublicKey: input.nextPublicKey,
  }, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signV3AndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ keyTransition: assembled.value });
}
