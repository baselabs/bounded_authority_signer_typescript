// The five companion-signer entry points — the port of BARA's public surface.
// This library SIGNS; the verifier package verifies. Every compact produced
// here is verified by the signer package's own test oracle through the
// verifier package before release.
import {
  boundaryAnchorSigningInput,
  grantSigningInput,
  keyTransitionSigningInput,
  localLoopbackHttpProofSigningInput,
  proofSigningInput,
  type Bounds,
  type KeyTransitionProducer,
  type BoundaryAnchorProducer,
  type GrantProducer,
  type OperationInput,
  type ProofProducer,
  type Tagged,
} from "@bounded-authority-protocol/verifier";
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

export interface SignerEvent {
  readonly kind: "report" | "local_loopback_report" | "anchor" | "grant" | "key_transition";
  readonly phase: "start" | "stop" | "error";
}

export interface SignOpts {
  readonly bounds?: Bounds;
  readonly issuedAt?: number;    // default: wall clock seconds
  readonly proofId?: string;     // default: crypto.randomUUID()
  readonly anchoredAt?: number;  // anchor timestamp (default: wall clock seconds)
  readonly onEvent?: (event: SignerEvent) => void;
}

export interface ReportInput {
  readonly grantCompact: Uint8Array;
  readonly operation: string;
  readonly method: string;
  readonly targetUri: string;
  readonly invocationId: string;
  readonly castArguments: Tagged;
  readonly nonce?: string;       // REQUIRED (non-empty) on the loopback profile
}

export interface AnchorInput {
  readonly anchorId: string;
  readonly chainId: string;
  readonly sequence: number;
  readonly chainHash: Uint8Array; // 32 bytes
}

export interface GrantInput {
  readonly issuer: string;
  readonly grantId: string;
  readonly audiences: readonly string[];
  readonly issuedAt: number;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly holderThumbprint: string;
  readonly operations: readonly OperationInput[];
}

export interface TransitionInput {
  readonly transitionId: string;
  readonly chainId: string;
  readonly effectiveAt: number;
  readonly nextKeyId: string;
  readonly nextPublicKey: Uint8Array; // 32 bytes
}

export interface Envelope { readonly grant: Uint8Array; readonly proof: Uint8Array }
export interface AnchorCompact { readonly anchor: Uint8Array }
export interface GrantCompact { readonly grant: Uint8Array }
export interface TransitionCompact { readonly keyTransition: Uint8Array }

const nowSeconds = () => Math.floor(Date.now() / 1000);
const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isU8 = (v: unknown, n?: number): v is Uint8Array => v instanceof Uint8Array && (n === undefined || v.length === n);

function validateReport(report: ReportInput, requireNonce: boolean): SignerResult<ReportInput> {
  if (!isU8(report?.grantCompact) || !isStr(report?.operation) || !isStr(report?.method) ||
      !isStr(report?.targetUri) || !isStr(report?.invocationId) || report?.castArguments === undefined) {
    return err("invalid_report");
  }
  if (report.nonce !== undefined && typeof report.nonce !== "string") return err("invalid_report");
  if (requireNonce && (report.nonce === undefined || report.nonce.length === 0)) return err("invalid_report");
  return ok(report);
}

function proofFrom(report: ReportInput, holderPublicKey: Uint8Array, proofId: string, issuedAt: number): ProofProducer {
  return {
    holderPublicKey, proofId, method: report.method, targetUri: report.targetUri,
    issuedAt, invocationId: report.invocationId, operation: report.operation,
    grantCompact: report.grantCompact, castArguments: report.castArguments,
    ...(report.nonce === undefined ? {} : { nonce: report.nonce }),
  };
}

async function signProofProfile(
  kind: "report" | "local_loopback_report",
  report: ReportInput,
  handle: KeyHandle,
  opts: SignOpts,
): Promise<SignerResult<Envelope>> {
  const emit = (phase: SignerEvent["phase"]) => opts.onEvent?.({ kind, phase });
  emit("start");
  const validated = validateReport(report, kind === "local_loopback_report");
  if (!validated.ok) { emit("error"); return validated; }

  const holderPublicKey = await resolvePublicKey(handle);
  if (holderPublicKey === undefined) { emit("error"); return err("invalid_key_handle"); }

  const proof = proofFrom(report, holderPublicKey, opts.proofId ?? crypto.randomUUID(), opts.issuedAt ?? nowSeconds());
  const produced = kind === "report"
    ? proofSigningInput(proof, opts.bounds)
    : localLoopbackHttpProofSigningInput(proof, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signAndAssemble(
    (m) => handle.sign(m), produced.value, holderPublicKey, opts.bounds,
    kind === "report" ? assemblers.standard : assemblers.loopback,
  );
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ grant: report.grantCompact, proof: assembled.value });
}

export function signReport(report: ReportInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<Envelope>> {
  return signProofProfile("report", report, handle, opts);
}

export function signLocalLoopbackReport(report: ReportInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<Envelope>> {
  return signProofProfile("local_loopback_report", report, handle, opts);
}

export async function signAnchor(input: AnchorInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<AnchorCompact>> {
  opts.onEvent?.({ kind: "anchor", phase: "start" });
  if (!isStr(input?.anchorId) || !isStr(input?.chainId) || !Number.isInteger(input?.sequence) || !isU8(input?.chainHash, 32)) {
    opts.onEvent?.({ kind: "anchor", phase: "error" });
    return err("invalid_anchor");
  }
  const identity = await resolveKeyIdentity(handle);
  if (identity === undefined) { opts.onEvent?.({ kind: "anchor", phase: "error" }); return err("invalid_key_handle"); }

  const anchor: BoundaryAnchorProducer = {
    anchorId: input.anchorId, anchoredAt: opts.anchoredAt ?? nowSeconds(), chainId: input.chainId,
    sequence: input.sequence, chainHash: input.chainHash, keyId: identity.keyId, publicKey: identity.publicKey,
  };
  const produced = boundaryAnchorSigningInput(anchor, opts.bounds);
  if (!produced.ok) { opts.onEvent?.({ kind: "anchor", phase: "error" }); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.standard);
  if (!assembled.ok) { opts.onEvent?.({ kind: "anchor", phase: "error" }); return assembled; }
  opts.onEvent?.({ kind: "anchor", phase: "stop" });
  return ok({ anchor: assembled.value });
}

export async function signGrant(input: GrantInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<GrantCompact>> {
  opts.onEvent?.({ kind: "grant", phase: "start" });
  if (!isStr(input?.issuer) || !isStr(input?.grantId) || !Array.isArray(input?.audiences) ||
      ![input?.issuedAt, input?.notBefore, input?.expiresAt].every(Number.isInteger) ||
      !isStr(input?.holderThumbprint) || !Array.isArray(input?.operations)) {
    opts.onEvent?.({ kind: "grant", phase: "error" });
    return err("invalid_grant");
  }
  // The C1 gate: only an issuer-role identity (resolved atomically) may sign a
  // grant — a holder handle (or one without signingIdentity) fails closed
  // BEFORE sign() is called.
  const identity = await resolveIssuerIdentity(handle);
  if (identity === undefined) { opts.onEvent?.({ kind: "grant", phase: "error" }); return err("invalid_key_handle"); }

  const grant: GrantProducer = {
    keyId: identity.keyId, issuer: input.issuer, grantId: input.grantId, audiences: [...input.audiences],
    issuedAt: input.issuedAt, notBefore: input.notBefore, expiresAt: input.expiresAt,
    holderThumbprint: input.holderThumbprint, operations: [...input.operations],
  };
  const produced = grantSigningInput(grant, opts.bounds);
  if (!produced.ok) { opts.onEvent?.({ kind: "grant", phase: "error" }); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.standard);
  if (!assembled.ok) { opts.onEvent?.({ kind: "grant", phase: "error" }); return assembled; }
  opts.onEvent?.({ kind: "grant", phase: "stop" });
  return ok({ grant: assembled.value });
}

export async function signKeyTransition(input: TransitionInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<TransitionCompact>> {
  opts.onEvent?.({ kind: "key_transition", phase: "start" });
  if (!isStr(input?.transitionId) || !isStr(input?.chainId) || !Number.isInteger(input?.effectiveAt) ||
      !isStr(input?.nextKeyId) || !isU8(input?.nextPublicKey, 32)) {
    opts.onEvent?.({ kind: "key_transition", phase: "error" });
    return err("invalid_transition");
  }
  const identity = await resolveKeyIdentity(handle);
  if (identity === undefined) { opts.onEvent?.({ kind: "key_transition", phase: "error" }); return err("invalid_key_handle"); }

  const transition: KeyTransitionProducer = {
    transitionId: input.transitionId, chainId: input.chainId, effectiveAt: input.effectiveAt,
    currentKeyId: identity.keyId, currentPublicKey: identity.publicKey,
    nextKeyId: input.nextKeyId, nextPublicKey: input.nextPublicKey,
  };
  const produced = keyTransitionSigningInput(transition, opts.bounds);
  if (!produced.ok) { opts.onEvent?.({ kind: "key_transition", phase: "error" }); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.standard);
  if (!assembled.ok) { opts.onEvent?.({ kind: "key_transition", phase: "error" }); return assembled; }
  opts.onEvent?.({ kind: "key_transition", phase: "stop" });
  return ok({ keyTransition: assembled.value });
}
