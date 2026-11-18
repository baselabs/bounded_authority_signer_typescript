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
  emitter,
  err,
  ok,
  resolveIssuerIdentity,
  resolveKeyIdentity,
  resolvePublicKey,
  type KeyHandle,
  type SignerResult,
} from "./handle.js";
import { defaultProofId } from "./proof-id.js";
import { selectorsHoldIntegralFloat } from "./selector-value.js";

/** A telemetry event from a v2 signer, passed to {@link V2SignOpts.onEvent}.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface V2SignerEvent {
  /** The signing operation that emitted this event. */
  readonly kind: "v2_report" | "v2_anchor" | "v2_grant" | "v2_key_transition";
  /** One start event, followed by one stop on success or error on failure. */
  readonly phase: "start" | "stop" | "error";
}

/** Options for the v2 signers: the same fields and defaults as `SignOpts`, with v2 event kinds.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface V2SignOpts {
  /** Size limits passed to the verifier's v2 producers and assembler. */
  readonly bounds?: Bounds;
  /** The proof's `iat` in Unix seconds (`signV2Report`). Default: the wall clock. */
  readonly issuedAt?: number;
  /** The proof's `jti` (`signV2Report`). Default: `crypto.randomUUID()`; where that is absent, `producer_error`. */
  readonly proofId?: string;
  /** The anchor timestamp in Unix seconds (`signV2Anchor`). Default: the wall clock. */
  readonly anchoredAt?: number;
  /** Called with a start event and then a stop or error event. A listener that throws is ignored. */
  readonly onEvent?: (event: V2SignerEvent) => void;
}

/** The request a v2 holder proof binds (`signV2Report`); the fields mean what they mean in `ReportInput`.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface V2ReportInput {
  /** The signed grant as ASCII compact JWS bytes; included unchanged in the returned envelope. */
  readonly grantCompact: Uint8Array;
  /** The operation name to bind; the resource must match it against a permitted grant operation. */
  readonly operation: string;
  /** RFC 9110 method token, 1 to 32 ASCII bytes (tightenable via method_bytes). Preserved exactly, without case folding. */
  readonly method: string;
  /** Already-normalized HTTPS request URI, at most 8,192 ASCII bytes (tightenable via uri_bytes). Noncanonical input is refused. */
  readonly targetUri: string;
  /** A lowercase RFC 4122 UUID identifying one logical invocation; the host runtime reserves it for single use. */
  readonly invocationId: string;
  /** Typed request arguments whose canonical projection is committed to by the proof digest. */
  readonly castArguments: Tagged;
  /** Optional server-issued nonce to bind into the proof. */
  readonly nonce?: string;
}

/** A v2 boundary anchor (`signV2Anchor`); the fields mean what they mean in `AnchorInput`.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface V2AnchorInput {
  /** A non-empty identifier for this boundary anchor. */
  readonly anchorId: string;
  /** A non-empty identifier for the consumption chain. */
  readonly chainId: string;
  /** The covered chain sequence number, a non-negative integer. */
  readonly sequence: number;
  /** The chain hash at the covered sequence, exactly 32 bytes. */
  readonly chainHash: Uint8Array; // 32 bytes
}

/** A v2 selector: the v1 kinds plus `lte` / `gte` with an integer- or float-tagged bound.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export type V2SelectorInput =
  | "all"
  | {
    /** Match all arguments without a value constraint. */
    readonly kind: "all"
  }
  | {
    /** Require typed equality at the path. */
    readonly kind: "equals";
    /** Member names locating the value within the typed request arguments. */
    readonly path: readonly string[];
    /** Required typed value; float-tagged integral numbers are refused at any depth. */
    readonly value: Tagged
  }
  | {
    /** Require membership in the typed values at the path. */
    readonly kind: "one_of";
    /** Member names locating the value within the typed request arguments. */
    readonly path: readonly string[];
    /** Allowed typed values; float-tagged integral numbers are refused at any depth. */
    readonly values: readonly Tagged[]
  }
  | {
    /** Require a numeric value with the same int or float tag to be at most the inclusive bound. */
    readonly kind: "lte";
    /** Member names locating the value within the typed request arguments. */
    readonly path: readonly string[];
    /** Numeric int- or float-tagged bound; a float-tagged integral value is refused. */
    readonly value: Tagged
  }
  | {
    /** Require a numeric value with the same int or float tag to be at least the inclusive bound. */
    readonly kind: "gte";
    /** Member names locating the value within the typed request arguments. */
    readonly path: readonly string[];
    /** Numeric int- or float-tagged bound; a float-tagged integral value is refused. */
    readonly value: Tagged
  };

/** One operation a v2 grant allows, with its selectors.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface V2OperationInput {
  /** A non-empty operation name. */
  readonly name: string;
  /** The argument constraints for this operation; every selector must match at verification. */
  readonly selectors: readonly V2SelectorInput[];
}

/** A v2 capability grant (`signV2Grant`); the fields mean what they mean in `GrantInput`, with v2 selectors.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface V2GrantInput {
  /** The issuer identifier as a StringOrURI, for example https://issuer.example. */
  readonly issuer: string;
  /** A non-empty identifier for the grant. */
  readonly grantId: string;
  /** The intended resource audiences; at least one. */
  readonly audiences: readonly string[];
  /** The issuance time (`iat`) in integer Unix seconds. */
  readonly issuedAt: number;
  /** The start of the grant validity window (`nbf`) in integer Unix seconds. */
  readonly notBefore: number;
  /** The end of the grant validity window (`exp`) in integer Unix seconds; after `notBefore`. */
  readonly expiresAt: number;
  /** The holder’s RFC 7638 OKP JWK thumbprint as unpadded base64url. */
  readonly holderThumbprint: string; // RFC 7638 OKP thumbprint, base64url
  /** At least one operation and its argument selectors; granting these bounds does not replace host authorization policy. */
  readonly operations: readonly V2OperationInput[];
}

/** A v2 key transition (`signV2KeyTransition`); the fields mean what they mean in `TransitionInput`.
 * @see [Guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/api-overview.md)
 */
export interface V2TransitionInput {
  /** A non-empty identifier for the key transition. */
  readonly transitionId: string;
  /** A non-empty identifier for the consumption chain. */
  readonly chainId: string;
  /** The next key activation time in integer Unix seconds. */
  readonly effectiveAt: number;
  /** The next key’s non-empty identifier. */
  readonly nextKeyId: string;
  /** The next key’s 32-byte raw Ed25519 public key. */
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

/**
 * Sign a contract-major-2 holder proof. Same handle, checks and errors as `signReport`.
 *
 * @returns `{ ok: true, value: { grant, proof } }`, or `invalid_report`, `invalid_key_handle`,
 *   `producer_error` or `signing_failed`.
 * @category Grant and proof — major 2
 * @see [Integrator guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/contract-major-2.md)
 * @example
 * <!-- readme-sample: run-dom -->
 * ```ts
 * import { ed25519KeyHandle, signV2Grant, signV2Report } from "@bounded-authority-protocol/signer";
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
 * const grant = await signV2Grant({ issuer: "https://issuer.example", grantId: "urn:example:grant:1",
 *   audiences: ["https://resource.example"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
 *   holderThumbprint: await made.value.thumbprint(),
 *   operations: [{ name: "read", selectors: [{ kind: "all" }] }] }, made.value);
 * if (!grant.ok) throw new Error(grant.error);
 * const result = await signV2Report({ grantCompact: grant.value.grant, operation: "read", method: "POST",
 *   targetUri: "https://resource.example/read", invocationId: "550e8400-e29b-41d4-a716-446655440000",
 *   castArguments: { t: "null" } }, made.value, { issuedAt: 1500, proofId: "urn:example:proof:1" });
 * if (!result.ok) throw new Error(result.error);
 * if (new TextDecoder().decode(result.value.proof).split(".").length !== 3) throw new Error("missing compact");
 * console.log("signV2Report: compact assembled");
 * ```
 * <!-- readme-output -->
 * ```text
 * signV2Report: compact assembled
 * ```
 */
export async function signV2Report(report: V2ReportInput, handle: KeyHandle, opts: V2SignOpts = {}): Promise<SignerResult<Envelope>> {
  const emit = emitter(opts, "v2_report");
  emit("start");
  const validated = validateReport(report);
  if (!validated.ok) { emit("error"); return validated; }

  const holderPublicKey = await resolvePublicKey(handle);
  if (holderPublicKey === undefined) { emit("error"); return err("invalid_key_handle"); }

  const proofId = defaultProofId(opts.proofId);
  if (proofId === undefined) { emit("error"); return err("producer_error"); }

  const produced = v2.proofSigningInput({
    holderPublicKey, proofId, method: report.method, targetUri: report.targetUri,
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

/**
 * Sign a contract-major-2 boundary anchor. Same handle (`keyIdentity()` required), checks and errors as `signAnchor`.
 *
 * @returns `{ ok: true, value: { anchor } }`, or `invalid_anchor`, `invalid_key_handle`, `producer_error` or `signing_failed`.
 * @category Anchors and transitions — major 2
 * @see [Integrator guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/rotate-keys.md)
 * @example
 * <!-- readme-sample: run-dom -->
 * ```ts
 * import { ed25519KeyHandle, signV2Anchor } from "@bounded-authority-protocol/signer";
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
 * const result = await signV2Anchor({ anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:1",
 *   sequence: 0, chainHash: new Uint8Array(32) }, made.value, { anchoredAt: 1500 });
 * if (!result.ok) throw new Error(result.error);
 * if (new TextDecoder().decode(result.value.anchor).split(".").length !== 3) throw new Error("missing compact");
 * console.log("signV2Anchor: compact assembled");
 * ```
 * <!-- readme-output -->
 * ```text
 * signV2Anchor: compact assembled
 * ```
 */
export async function signV2Anchor(input: V2AnchorInput, handle: KeyHandle, opts: V2SignOpts = {}): Promise<SignerResult<AnchorCompact>> {
  const emit = emitter(opts, "v2_anchor");
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

/**
 * Sign a contract-major-2 capability grant. Issuer-only: the issuer-role gate of `signGrant` applies.
 *
 * @returns `{ ok: true, value: { grant } }`, or `invalid_grant`, `invalid_key_handle`, `producer_error` or `signing_failed`.
 * @category Grant and proof — major 2
 * @see [Integrator guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/contract-major-2.md)
 * @example
 * <!-- readme-sample: run-dom -->
 * ```ts
 * import { ed25519KeyHandle, signV2Grant } from "@bounded-authority-protocol/signer";
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
 * const result = await signV2Grant({ issuer: "https://issuer.example", grantId: "urn:example:grant:1",
 *   audiences: ["https://resource.example"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
 *   holderThumbprint: await made.value.thumbprint(),
 *   operations: [{ name: "read", selectors: [{ kind: "all" }] }] }, made.value);
 * if (!result.ok) throw new Error(result.error);
 * if (new TextDecoder().decode(result.value.grant).split(".").length !== 3) throw new Error("missing compact");
 * console.log("signV2Grant: compact assembled");
 * ```
 * <!-- readme-output -->
 * ```text
 * signV2Grant: compact assembled
 * ```
 */
export async function signV2Grant(input: V2GrantInput, handle: KeyHandle, opts: V2SignOpts = {}): Promise<SignerResult<GrantCompact>> {
  const emit = emitter(opts, "v2_grant");
  emit("start");
  if (!isStr(input?.issuer) || !isStr(input?.grantId) || !Array.isArray(input?.audiences) ||
      ![input?.issuedAt, input?.notBefore, input?.expiresAt].every(Number.isInteger) ||
      !isStr(input?.holderThumbprint) || !Array.isArray(input?.operations)) {
    emit("error");
    return err("invalid_grant");
  }
  // Only an issuer-role identity, resolved atomically, may sign a grant. A holder handle
  // (or one without signingIdentity) fails closed BEFORE sign() is called.
  const identity = await resolveIssuerIdentity(handle);
  if (identity === undefined) { emit("error"); return err("invalid_key_handle"); }

  let operations: v2.OperationInput[];
  try {
    operations = toProducerOperations(input.operations);
  } catch {
    // A malformed operation or selector entry goes to the verifier's producer as given, which refuses
    // it: producer_error, the same closed error v1 and v3 return for the same input.
    operations = [...input.operations] as unknown as v2.OperationInput[];
  }
  const produced = v2.grantSigningInput({
    keyId: identity.keyId, issuer: input.issuer, grantId: input.grantId, audiences: [...input.audiences],
    issuedAt: input.issuedAt, notBefore: input.notBefore, expiresAt: input.expiresAt,
    holderThumbprint: input.holderThumbprint, operations,
  }, opts.bounds);
  if (!produced.ok || selectorsHoldIntegralFloat(operations)) { emit("error"); return err("producer_error"); }

  const assembled = await signAndAssemble((m) => handle.sign(m), produced.value, identity.publicKey, opts.bounds, assemblers.v2);
  if (!assembled.ok) { emit("error"); return assembled; }
  emit("stop");
  return ok({ grant: assembled.value });
}

/**
 * Sign a contract-major-2 key transition. Same handle (`keyIdentity()` required), checks and errors as `signKeyTransition`.
 *
 * @returns `{ ok: true, value: { keyTransition } }`, or `invalid_transition`, `invalid_key_handle`, `producer_error` or `signing_failed`.
 * @category Anchors and transitions — major 2
 * @see [Integrator guide](https://github.com/baselabs/bounded_authority_signer_typescript/blob/main/docs/guides/rotate-keys.md)
 * @example
 * <!-- readme-sample: run-dom -->
 * ```ts
 * import { ed25519KeyHandle, signV2KeyTransition } from "@bounded-authority-protocol/signer";
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
 * const result = await signV2KeyTransition({ transitionId: "urn:example:transition:1", chainId: "urn:example:chain:1",
 *   effectiveAt: 1600, nextKeyId: "next-key", nextPublicKey: await next.value.publicKey() }, made.value);
 * if (!result.ok) throw new Error(result.error);
 * if (new TextDecoder().decode(result.value.keyTransition).split(".").length !== 3) throw new Error("missing compact");
 * console.log("signV2KeyTransition: compact assembled");
 * ```
 * <!-- readme-output -->
 * ```text
 * signV2KeyTransition: compact assembled
 * ```
 */
export async function signV2KeyTransition(input: V2TransitionInput, handle: KeyHandle, opts: V2SignOpts = {}): Promise<SignerResult<TransitionCompact>> {
  const emit = emitter(opts, "v2_key_transition");
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
