// The four contract-major-2 companion signers. Before 0.5.0 contract-major 2 had no signing surface in
// this package: the verifier package exposes the v2 signing inputs (v2.grantSigningInput,
// v2.proofSigningInput, v2.boundaryAnchorSigningInput, v2.keyTransitionSigningInput) and
// v2.assembleCompact, and these functions put the existing caller-owned Ed25519 KeyHandle in front of
// them. Same structure as api.ts: validate the input -> resolve the handle's identity atomically (the
// same resolvers, including the weak-key refusal) -> compose through the verifier's public v2
// producers -> sign through the shared tail (sign.ts: sign -> strict verify -> v2 assemble).
//
// The v2 wire format is the verifier's (v:2 payloads, BAP2-* domain separators, the five-kind selector
// algebra with lte/gte); nothing here adds a member, a kind, or a byte beyond it. The local-loopback
// profile is contract-major-1 bound and has no v2 form.
import { v2, type Bounds, type Tagged } from "@bounded-authority-protocol/verifier";
import type { AnchorCompact, Envelope, GrantCompact, TransitionCompact } from "./api.js";
import { assemblers, signAndAssemble } from "./sign.js";
import {
  err,
  ok,
  resolveIssuerIdentity,
  resolveKeyIdentity,
  resolvePublicKey,
  type KeyHandle,
  type SignerResult,
} from "./handle.js";

export interface V2SignerEvent {
  readonly kind: "v2_report" | "v2_anchor" | "v2_grant" | "v2_key_transition";
  readonly phase: "start" | "stop" | "error";
}

export interface V2SignOpts {
  readonly bounds?: Bounds;
  readonly issuedAt?: number;    // default: wall clock seconds
  readonly proofId?: string;     // default: crypto.randomUUID()
  readonly anchoredAt?: number;  // anchor timestamp (default: wall clock seconds)
  readonly onEvent?: (event: V2SignerEvent) => void;
}

export interface V2ReportInput {
  readonly grantCompact: Uint8Array;
  readonly operation: string;
  readonly method: string;
  readonly targetUri: string;
  readonly invocationId: string;
  readonly castArguments: Tagged;
  readonly nonce?: string;
}

export interface V2AnchorInput {
  readonly anchorId: string;
  readonly chainId: string;
  readonly sequence: number;
  readonly chainHash: Uint8Array; // 32 bytes
}

/** A v2 selector: the v1 kinds plus `lte` / `gte` with an integer- or float-tagged bound. */
export type V2SelectorInput =
  | "all"
  | { readonly kind: "all" }
  | { readonly kind: "equals"; readonly path: readonly string[]; readonly value: Tagged }
  | { readonly kind: "one_of"; readonly path: readonly string[]; readonly values: readonly Tagged[] }
  | { readonly kind: "lte"; readonly path: readonly string[]; readonly value: Tagged }
  | { readonly kind: "gte"; readonly path: readonly string[]; readonly value: Tagged };

export interface V2OperationInput {
  readonly name: string;
  readonly selectors: readonly V2SelectorInput[];
}

export interface V2GrantInput {
  readonly issuer: string;
  readonly grantId: string;
  readonly audiences: readonly string[];
  readonly issuedAt: number;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly holderThumbprint: string; // RFC 7638 OKP thumbprint, base64url
  readonly operations: readonly V2OperationInput[];
}

export interface V2TransitionInput {
  readonly transitionId: string;
  readonly chainId: string;
  readonly effectiveAt: number;
  readonly nextKeyId: string;
  readonly nextPublicKey: Uint8Array; // 32 bytes
}

const nowSeconds = () => Math.floor(Date.now() / 1000);
const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isU8 = (v: unknown, n?: number): v is Uint8Array => v instanceof Uint8Array && (n === undefined || v.length === n);

// The verifier's producer types take mutable arrays; copy the caller's readonly ones.
function toProducerOperations(operations: readonly V2OperationInput[]): v2.OperationInput[] {
  return operations.map((op) => ({
    name: op.name,
    selectors: op.selectors.map((sel): v2.SelectorInput => {
      if (sel === "all" || sel.kind === "all") return sel;
      if (sel.kind === "one_of") return { kind: "one_of", path: [...sel.path], values: [...sel.values] };
      return { kind: sel.kind, path: [...sel.path], value: sel.value };
    }),
  }));
}

function validateReport(report: V2ReportInput): SignerResult<V2ReportInput> {
  if (!isU8(report?.grantCompact) || !isStr(report?.operation) || !isStr(report?.method) ||
      !isStr(report?.targetUri) || !isStr(report?.invocationId) || report?.castArguments === undefined) {
    return err("invalid_report");
  }
  if (report.nonce !== undefined && typeof report.nonce !== "string") return err("invalid_report");
  return ok(report);
}

export async function signV2Report(report: V2ReportInput, handle: KeyHandle, opts: V2SignOpts = {}): Promise<SignerResult<Envelope>> {
  const emit = (phase: V2SignerEvent["phase"]) => opts.onEvent?.({ kind: "v2_report", phase });
  emit("start");
  const validated = validateReport(report);
  if (!validated.ok) { emit("error"); return validated; }

  const holderPublicKey = await resolvePublicKey(handle);
  if (holderPublicKey === undefined) { emit("error"); return err("invalid_key_handle"); }

  const produced = v2.proofSigningInput({
    holderPublicKey, proofId: opts.proofId ?? crypto.randomUUID(), method: report.method, targetUri: report.targetUri,
    issuedAt: opts.issuedAt ?? nowSeconds(), invocationId: report.invocationId, operation: report.operation,
    grantCompact: report.grantCompact, castArguments: report.castArguments,
    ...(report.nonce === undefined ? {} : { nonce: report.nonce }),
  }, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, holderPublicKey, opts.bounds, assemblers.v2);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ grant: report.grantCompact, proof: assembled.value });
}

export async function signV2Anchor(input: V2AnchorInput, handle: KeyHandle, opts: V2SignOpts = {}): Promise<SignerResult<AnchorCompact>> {
  const emit = (phase: V2SignerEvent["phase"]) => opts.onEvent?.({ kind: "v2_anchor", phase });
  emit("start");
  if (!isStr(input?.anchorId) || !isStr(input?.chainId) || !Number.isInteger(input?.sequence) || !isU8(input?.chainHash, 32)) {
    emit("error");
    return err("invalid_anchor");
  }
  const identity = await resolveKeyIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  const produced = v2.boundaryAnchorSigningInput({
    anchorId: input.anchorId, anchoredAt: opts.anchoredAt ?? nowSeconds(), chainId: input.chainId,
    sequence: input.sequence, chainHash: input.chainHash, keyId: identity.keyId, publicKey: identity.publicKey,
  }, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.v2);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ anchor: assembled.value });
}

export async function signV2Grant(input: V2GrantInput, handle: KeyHandle, opts: V2SignOpts = {}): Promise<SignerResult<GrantCompact>> {
  const emit = (phase: V2SignerEvent["phase"]) => opts.onEvent?.({ kind: "v2_grant", phase });
  emit("start");
  if (!isStr(input?.issuer) || !isStr(input?.grantId) || !Array.isArray(input?.audiences) ||
      ![input?.issuedAt, input?.notBefore, input?.expiresAt].every(Number.isInteger) ||
      !isStr(input?.holderThumbprint) || !Array.isArray(input?.operations)) {
    emit("error");
    return err("invalid_grant");
  }
  // The C1 gate: only an issuer-role identity (resolved atomically) may sign a grant — a holder handle
  // (or one without signingIdentity) fails closed BEFORE sign() is called.
  const identity = await resolveIssuerIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  let operations: v2.OperationInput[];
  try {
    operations = toProducerOperations(input.operations);
  } catch {
    emit("error");
    return err("invalid_grant"); // a malformed operation or selector shape
  }
  const produced = v2.grantSigningInput({
    keyId: identity.keyId, issuer: input.issuer, grantId: input.grantId, audiences: [...input.audiences],
    issuedAt: input.issuedAt, notBefore: input.notBefore, expiresAt: input.expiresAt,
    holderThumbprint: input.holderThumbprint, operations,
  }, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.v2);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ grant: assembled.value });
}

export async function signV2KeyTransition(input: V2TransitionInput, handle: KeyHandle, opts: V2SignOpts = {}): Promise<SignerResult<TransitionCompact>> {
  const emit = (phase: V2SignerEvent["phase"]) => opts.onEvent?.({ kind: "v2_key_transition", phase });
  emit("start");
  if (!isStr(input?.transitionId) || !isStr(input?.chainId) || !Number.isInteger(input?.effectiveAt) ||
      !isStr(input?.nextKeyId) || !isU8(input?.nextPublicKey, 32)) {
    emit("error");
    return err("invalid_transition");
  }
  const identity = await resolveKeyIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  const produced = v2.keyTransitionSigningInput({
    transitionId: input.transitionId, chainId: input.chainId, effectiveAt: input.effectiveAt,
    currentKeyId: identity.keyId, currentPublicKey: identity.publicKey,
    nextKeyId: input.nextKeyId, nextPublicKey: input.nextPublicKey,
  }, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.v2);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ keyTransition: assembled.value });
}
