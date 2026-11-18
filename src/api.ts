// The five companion-signer entry points mirror the Elixir
// bounded_authority_report_adapter's public surface.
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
import { defaultProofId } from "./proof-id.js";
import { selectorsHoldIntegralFloat } from "./selector-value.js";
import {
  emitter,
  err,
  ok,
  resolveIssuerIdentity,
  resolveKeyIdentity,
  resolvePublicKey,
  type KeyHandle,
  type SignerResult,
} from "./handle.js";

/** A telemetry event from a v1 signer, passed to {@link SignOpts.onEvent}: one `start`, then one `stop` or `error`.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface SignerEvent {
  /** The signing operation that emitted this event. */
  readonly kind: "report" | "local_loopback_report" | "anchor" | "grant" | "key_transition";
  /** One start event, followed by one stop on success or error on failure. */
  readonly phase: "start" | "stop" | "error";
}

/** Options for the v1 signers. Every field is optional.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface SignOpts {
  /** Size limits passed to the verifier's producers and assembler (default: the verifier's defaults). */
  readonly bounds?: Bounds;
  /** The proof's `iat` in Unix seconds (report signers). Default: the wall clock. */
  readonly issuedAt?: number;
  /** The proof's `jti` (report signers). Default: `crypto.randomUUID()`; where that is absent (a plain-HTTP page) the result is `producer_error`. */
  readonly proofId?: string;
  /** The anchor timestamp in Unix seconds (`signAnchor`). Default: the wall clock. */
  readonly anchoredAt?: number;
  /** Called with a start event and then a stop or error event. A listener that throws is ignored. */
  readonly onEvent?: (event: SignerEvent) => void;
}

/** The request a holder proof binds (`signReport`, `signLocalLoopbackReport`).
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface ReportInput {
  /** The signed grant compact, as `signGrant` returned it. It passes through to the envelope untouched. */
  readonly grantCompact: Uint8Array;
  /** Operation name, 1 to 128 printable ASCII bytes. The resource verifies grant membership; signing does not authenticate the grant. */
  readonly operation: string;
  /** RFC 9110 method token, 1 to 32 ASCII bytes (tightenable via method_bytes). Preserved exactly, without case folding. */
  readonly method: string;
  /** Already-normalized request URI, at most 8,192 ASCII bytes (tightenable via uri_bytes). HTTPS by default. On the loopback profile: `http://127.0.0.1[:port]/…` or `http://[::1][:port]/…` only. */
  readonly targetUri: string;
  /** The invocation id: a lowercase RFC 4122 UUID (anything else is `producer_error`). */
  readonly invocationId: string;
  /** The request's arguments as the verifier's type-tagged JSON value; the proof commits to their digest. */
  readonly castArguments: Tagged;
  /** A server-issued nonce. Required (non-empty) by `signLocalLoopbackReport`; optional for `signReport`. */
  readonly nonce?: string;
}

/** A boundary anchor: a signed checkpoint of a hash chain (`signAnchor`).
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface AnchorInput {
  /** A non-empty anchor id. */
  readonly anchorId: string;
  /** A non-empty chain id. */
  readonly chainId: string;
  /** The chain sequence number this anchor covers: a non-negative integer. */
  readonly sequence: number;
  /** The chain hash at that sequence: exactly 32 bytes. */
  readonly chainHash: Uint8Array;
}

/** A capability grant (`signGrant`). The issuer key id comes from the handle's `signingIdentity()`.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface GrantInput {
  /** The issuer identifier (a StringOrURI, for example `https://issuer.example`). */
  readonly issuer: string;
  /** A non-empty grant id. */
  readonly grantId: string;
  /** The resources the grant is for; at least one. */
  readonly audiences: readonly string[];
  /** The issuance time (`iat`) in integer Unix seconds. */
  readonly issuedAt: number;
  /** The start of the grant validity window (`nbf`) in integer Unix seconds. */
  readonly notBefore: number;
  /** The end of the grant validity window (`exp`) in integer Unix seconds; after `notBefore`. */
  readonly expiresAt: number;
  /** The holder key's RFC 7638 JWK thumbprint, base64url (the holder handle's `thumbprint()`). */
  readonly holderThumbprint: string;
  /** The operations the holder may invoke, each with its selectors (`all`, `equals`, `one_of`); at least one. */
  readonly operations: readonly OperationInput[];
}

/** A key transition: the current key (the handle's) hands a chain to the next key (`signKeyTransition`).
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface TransitionInput {
  /** A non-empty transition id. */
  readonly transitionId: string;
  /** The chain the transition applies to. */
  readonly chainId: string;
  /** When the next key takes over, in Unix seconds (an integer). */
  readonly effectiveAt: number;
  /** The next key's non-empty key id. */
  readonly nextKeyId: string;
  /** The next key's raw Ed25519 public key: exactly 32 bytes. */
  readonly nextPublicKey: Uint8Array;
}

/** A report signer's value: the grant compact (unchanged) and the new proof compact, both ASCII bytes.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface Envelope {
  /** The unchanged grant as ASCII compact JWS bytes. */
  readonly grant: Uint8Array;
  /** The fresh holder proof as ASCII compact JWS bytes. */
  readonly proof: Uint8Array
}
/** An anchor signer's value: the anchor compact.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface AnchorCompact {
  /** The signed boundary anchor as ASCII compact JWS bytes. */
  readonly anchor: Uint8Array
}
/** A grant signer's value: the grant compact.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface GrantCompact {
  /** The signed grant as ASCII compact JWS bytes. */
  readonly grant: Uint8Array
}
/** A key-transition signer's value: the transition compact.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface TransitionCompact {
  /** The signed key transition as ASCII compact JWS bytes. */
  readonly keyTransition: Uint8Array
}

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
  const emit = emitter(opts, kind);
  emit("start");
  const validated = validateReport(report, kind === "local_loopback_report");
  if (!validated.ok) { emit("error"); return validated; }

  const holderPublicKey = await resolvePublicKey(handle);
  if (holderPublicKey === undefined) { emit("error"); return err("invalid_key_handle"); }

  const proofId = defaultProofId(opts.proofId);
  if (proofId === undefined) { emit("error"); return err("producer_error"); }

  const proof = proofFrom(report, holderPublicKey, proofId, opts.issuedAt ?? nowSeconds());
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

/**
 * Sign a holder proof that binds one request to a grant (contract-major 1).
 *
 * Uses `handle.publicKey()` and `handle.sign()`; no identity snapshot is needed.
 *
 * @returns `{ ok: true, value: { grant, proof } }`, or `{ ok: false, error }` with `invalid_report`
 *   (a missing or mistyped field), `invalid_key_handle`, `producer_error` (the verifier's producer
 *   refused an input, for example a non-UUID `invocationId`, or no default `proofId`) or `signing_failed`.
 * @category Grant and proof — major 1
 * @see [Integrator guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/getting-started.md)
 * @example
 * <!-- readme-sample: run-dom -->
 * ```ts
 * import { ed25519KeyHandle, signGrant, signReport } from "@bounded-authority-protocol/signer";
 * // WebKit for Linux can transiently refuse key generation; retry only OperationError.
 * async function generatePair(algorithm: Algorithm | EcKeyGenParams, extractable = false): Promise<CryptoKeyPair> {
 *   for (let attempt = 0; attempt < 3; attempt++) {
 *     try { return await crypto.subtle.generateKey(algorithm, extractable, ["sign", "verify"]) as CryptoKeyPair; }
 *     catch (error) { if ((error as { name?: string }).name !== "OperationError" || attempt === 2) throw error; }
 *   }
 *   throw new Error("key generation failed");
 * }
 *
 * const pair = await generatePair({ name: "Ed25519" });
 * const made = await ed25519KeyHandle(pair, { keyId: "example-key", role: "issuer" });
 * if (!made.ok) throw new Error(made.error);
 * const grant = await signGrant({ issuer: "https://issuer.example", grantId: "urn:example:grant:1",
 *   audiences: ["https://resource.example"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
 *   holderThumbprint: await made.value.thumbprint(),
 *   operations: [{ name: "read", selectors: [{ kind: "all" }] }] }, made.value);
 * if (!grant.ok) throw new Error(grant.error);
 * const result = await signReport({ grantCompact: grant.value.grant, operation: "read", method: "POST",
 *   targetUri: "https://resource.example/read", invocationId: "550e8400-e29b-41d4-a716-446655440000",
 *   castArguments: { t: "null" } }, made.value, { issuedAt: 1500, proofId: "urn:example:proof:1" });
 * if (!result.ok) throw new Error(result.error);
 * if (new TextDecoder().decode(result.value.proof).split(".").length !== 3) throw new Error("missing compact");
 * console.log("signReport: compact assembled");
 * ```
 * <!-- readme-output -->
 * ```text
 * signReport: compact assembled
 * ```
 */
export function signReport(report: ReportInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<Envelope>> {
  return signProofProfile("report", report, handle, opts);
}

/**
 * Sign a holder proof under the local-loopback application-proof profile (`ba+loopback-proof`).
 *
 * The profile is chosen by this function, never inferred: `report.nonce` is required, and
 * `report.targetUri` must be `http://127.0.0.1[:port]/…` or `http://[::1][:port]/…`.
 *
 * @returns As {@link signReport}; a missing nonce is `invalid_report`, any other target (`localhost`
 *   included) is `producer_error`.
 * @category Local loopback
 * @see [Integrator guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/local-loopback.md)
 * @example
 * <!-- readme-sample: run-dom -->
 * ```ts
 * import { ed25519KeyHandle, signGrant, signLocalLoopbackReport } from "@bounded-authority-protocol/signer";
 * // WebKit for Linux can transiently refuse key generation; retry only OperationError.
 * async function generatePair(algorithm: Algorithm | EcKeyGenParams, extractable = false): Promise<CryptoKeyPair> {
 *   for (let attempt = 0; attempt < 3; attempt++) {
 *     try { return await crypto.subtle.generateKey(algorithm, extractable, ["sign", "verify"]) as CryptoKeyPair; }
 *     catch (error) { if ((error as { name?: string }).name !== "OperationError" || attempt === 2) throw error; }
 *   }
 *   throw new Error("key generation failed");
 * }
 *
 * const pair = await generatePair({ name: "Ed25519" });
 * const made = await ed25519KeyHandle(pair, { keyId: "example-key", role: "issuer" });
 * if (!made.ok) throw new Error(made.error);
 * const grant = await signGrant({ issuer: "https://issuer.example", grantId: "urn:example:grant:1",
 *   audiences: ["https://resource.example"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
 *   holderThumbprint: await made.value.thumbprint(),
 *   operations: [{ name: "read", selectors: [{ kind: "all" }] }] }, made.value);
 * if (!grant.ok) throw new Error(grant.error);
 * const result = await signLocalLoopbackReport({ grantCompact: grant.value.grant, operation: "read", method: "POST",
 *   targetUri: "http://127.0.0.1:47321/rpc", invocationId: "550e8400-e29b-41d4-a716-446655440000",
 *   castArguments: { t: "null" }, nonce: "server-issued-challenge" }, made.value, { issuedAt: 1500, proofId: "urn:example:proof:1" });
 * if (!result.ok) throw new Error(result.error);
 * if (new TextDecoder().decode(result.value.proof).split(".").length !== 3) throw new Error("missing compact");
 * console.log("signLocalLoopbackReport: compact assembled");
 * ```
 * <!-- readme-output -->
 * ```text
 * signLocalLoopbackReport: compact assembled
 * ```
 */
export function signLocalLoopbackReport(report: ReportInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<Envelope>> {
  return signProofProfile("local_loopback_report", report, handle, opts);
}

/**
 * Sign a boundary anchor (contract-major 1). Role-agnostic.
 *
 * Needs `handle.keyIdentity()`: the key id and public key as one snapshot.
 *
 * @returns `{ ok: true, value: { anchor } }`, or `invalid_anchor`, `invalid_key_handle` (including a
 *   handle without `keyIdentity`), `producer_error` or `signing_failed`.
 * @category Anchors and transitions — major 1
 * @see [Integrator guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/rotate-keys.md)
 * @example
 * <!-- readme-sample: run-dom -->
 * ```ts
 * import { ed25519KeyHandle, signAnchor } from "@bounded-authority-protocol/signer";
 * // WebKit for Linux can transiently refuse key generation; retry only OperationError.
 * async function generatePair(algorithm: Algorithm | EcKeyGenParams, extractable = false): Promise<CryptoKeyPair> {
 *   for (let attempt = 0; attempt < 3; attempt++) {
 *     try { return await crypto.subtle.generateKey(algorithm, extractable, ["sign", "verify"]) as CryptoKeyPair; }
 *     catch (error) { if ((error as { name?: string }).name !== "OperationError" || attempt === 2) throw error; }
 *   }
 *   throw new Error("key generation failed");
 * }
 *
 * const pair = await generatePair({ name: "Ed25519" });
 * const made = await ed25519KeyHandle(pair, { keyId: "example-key", role: "issuer" });
 * if (!made.ok) throw new Error(made.error);
 * const result = await signAnchor({ anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:1",
 *   sequence: 0, chainHash: new Uint8Array(32) }, made.value, { anchoredAt: 1500 });
 * if (!result.ok) throw new Error(result.error);
 * if (new TextDecoder().decode(result.value.anchor).split(".").length !== 3) throw new Error("missing compact");
 * console.log("signAnchor: compact assembled");
 * ```
 * <!-- readme-output -->
 * ```text
 * signAnchor: compact assembled
 * ```
 */
export async function signAnchor(input: AnchorInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<AnchorCompact>> {
  const emit = emitter(opts, "anchor");
  emit("start");
  if (!isStr(input?.anchorId) || !isStr(input?.chainId) || !Number.isInteger(input?.sequence) || !isU8(input?.chainHash, 32)) {
    emit("error");
    return err("invalid_anchor");
  }
  const identity = await resolveKeyIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  const anchor: BoundaryAnchorProducer = {
    anchorId: input.anchorId, anchoredAt: opts.anchoredAt ?? nowSeconds(), chainId: input.chainId,
    sequence: input.sequence, chainHash: input.chainHash, keyId: identity.keyId, publicKey: identity.publicKey,
  };
  const produced = boundaryAnchorSigningInput(anchor, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.standard);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ anchor: assembled.value });
}

/**
 * Sign a capability grant (contract-major 1). Issuer-only.
 *
 * Reads `handle.signingIdentity()` once; unless its own `role` is `"issuer"` the result is
 * `invalid_key_handle` and `sign()` is never called (the issuer-role gate).
 *
 * @returns `{ ok: true, value: { grant } }`, or `invalid_grant`, `invalid_key_handle`,
 *   `producer_error` (for example no operations, no audiences, or `expiresAt` not after `notBefore`)
 *   or `signing_failed`.
 * @category Grant and proof — major 1
 * @see [Integrator guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/getting-started.md)
 * @example
 * <!-- readme-sample: run-dom -->
 * ```ts
 * import { ed25519KeyHandle, signGrant } from "@bounded-authority-protocol/signer";
 * // WebKit for Linux can transiently refuse key generation; retry only OperationError.
 * async function generatePair(algorithm: Algorithm | EcKeyGenParams, extractable = false): Promise<CryptoKeyPair> {
 *   for (let attempt = 0; attempt < 3; attempt++) {
 *     try { return await crypto.subtle.generateKey(algorithm, extractable, ["sign", "verify"]) as CryptoKeyPair; }
 *     catch (error) { if ((error as { name?: string }).name !== "OperationError" || attempt === 2) throw error; }
 *   }
 *   throw new Error("key generation failed");
 * }
 *
 * const pair = await generatePair({ name: "Ed25519" });
 * const made = await ed25519KeyHandle(pair, { keyId: "example-key", role: "issuer" });
 * if (!made.ok) throw new Error(made.error);
 * const result = await signGrant({ issuer: "https://issuer.example", grantId: "urn:example:grant:1",
 *   audiences: ["https://resource.example"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
 *   holderThumbprint: await made.value.thumbprint(),
 *   operations: [{ name: "read", selectors: [{ kind: "all" }] }] }, made.value);
 * if (!result.ok) throw new Error(result.error);
 * if (new TextDecoder().decode(result.value.grant).split(".").length !== 3) throw new Error("missing compact");
 * console.log("signGrant: compact assembled");
 * ```
 * <!-- readme-output -->
 * ```text
 * signGrant: compact assembled
 * ```
 */
export async function signGrant(input: GrantInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<GrantCompact>> {
  const emit = emitter(opts, "grant");
  emit("start");
  if (!isStr(input?.issuer) || !isStr(input?.grantId) || !Array.isArray(input?.audiences) ||
      ![input?.issuedAt, input?.notBefore, input?.expiresAt].every(Number.isInteger) ||
      !isStr(input?.holderThumbprint) || !Array.isArray(input?.operations)) {
    emit("error");
    return err("invalid_grant");
  }
  // The issuer-role gate: only an issuer-role identity (resolved atomically) may sign a
  // grant. A holder handle (or one without signingIdentity) fails closed
  // BEFORE sign() is called.
  const identity = await resolveIssuerIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  const grant: GrantProducer = {
    keyId: identity.keyId, issuer: input.issuer, grantId: input.grantId, audiences: [...input.audiences],
    issuedAt: input.issuedAt, notBefore: input.notBefore, expiresAt: input.expiresAt,
    holderThumbprint: input.holderThumbprint, operations: [...input.operations],
  };
  const produced = grantSigningInput(grant, opts.bounds);
  if (!produced.ok || selectorsHoldIntegralFloat(input.operations)) { emit("error"); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.standard);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ grant: assembled.value });
}

/**
 * Sign a key transition from the handle's key to `input.nextPublicKey` (contract-major 1). Role-agnostic.
 *
 * Needs `handle.keyIdentity()`.
 *
 * @returns `{ ok: true, value: { keyTransition } }`, or `invalid_transition`, `invalid_key_handle`,
 *   `producer_error` or `signing_failed`.
 * @category Anchors and transitions — major 1
 * @see [Integrator guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/rotate-keys.md)
 * @example
 * <!-- readme-sample: run-dom -->
 * ```ts
 * import { ed25519KeyHandle, signKeyTransition } from "@bounded-authority-protocol/signer";
 * // WebKit for Linux can transiently refuse key generation; retry only OperationError.
 * async function generatePair(algorithm: Algorithm | EcKeyGenParams, extractable = false): Promise<CryptoKeyPair> {
 *   for (let attempt = 0; attempt < 3; attempt++) {
 *     try { return await crypto.subtle.generateKey(algorithm, extractable, ["sign", "verify"]) as CryptoKeyPair; }
 *     catch (error) { if ((error as { name?: string }).name !== "OperationError" || attempt === 2) throw error; }
 *   }
 *   throw new Error("key generation failed");
 * }
 *
 * const pair = await generatePair({ name: "Ed25519" });
 * const made = await ed25519KeyHandle(pair, { keyId: "example-key", role: "issuer" });
 * if (!made.ok) throw new Error(made.error);
 * const nextPair = await generatePair({ name: "Ed25519" });
 * const next = await ed25519KeyHandle(nextPair, { keyId: "next-key" });
 * if (!next.ok) throw new Error(next.error);
 * const result = await signKeyTransition({ transitionId: "urn:example:transition:1", chainId: "urn:example:chain:1",
 *   effectiveAt: 1600, nextKeyId: "next-key", nextPublicKey: await next.value.publicKey() }, made.value);
 * if (!result.ok) throw new Error(result.error);
 * if (new TextDecoder().decode(result.value.keyTransition).split(".").length !== 3) throw new Error("missing compact");
 * console.log("signKeyTransition: compact assembled");
 * ```
 * <!-- readme-output -->
 * ```text
 * signKeyTransition: compact assembled
 * ```
 */
export async function signKeyTransition(input: TransitionInput, handle: KeyHandle, opts: SignOpts = {}): Promise<SignerResult<TransitionCompact>> {
  const emit = emitter(opts, "key_transition");
  emit("start");
  if (!isStr(input?.transitionId) || !isStr(input?.chainId) || !Number.isInteger(input?.effectiveAt) ||
      !isStr(input?.nextKeyId) || !isU8(input?.nextPublicKey, 32)) {
    emit("error");
    return err("invalid_transition");
  }
  const identity = await resolveKeyIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  const transition: KeyTransitionProducer = {
    transitionId: input.transitionId, chainId: input.chainId, effectiveAt: input.effectiveAt,
    currentKeyId: identity.keyId, currentPublicKey: identity.publicKey,
    nextKeyId: input.nextKeyId, nextPublicKey: input.nextPublicKey,
  };
  const produced = keyTransitionSigningInput(transition, opts.bounds);
  if (!produced.ok) { emit("error"); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.standard);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ keyTransition: assembled.value });
}
