// The four contract-major-3 companion signers mirror the
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
  isOnCurveP256,
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

/**
 * The ES256 key-handle contract (contract-major 3): the same caller-owned custody as `KeyHandle`, with
 * the suite's widths. `sign()` returns the 64-byte raw `r || s` (a high `s` is fine: the library
 * normalizes it to low-S before emission), `publicKey()` the 65-byte uncompressed SEC1 point
 * (`0x04 || x || y`, on P-256), and `thumbprint()` the RFC 7638 EC thumbprint (base64url). Every method
 * may return a Promise. The private key never enters this library.
 */
export interface Es256KeyHandle {
  /** Sign a copy of the standard JWS signing input using caller-owned custody. Return 64-byte raw `r || s`; the signer normalizes high-S signatures. */
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>; // 64-byte raw r || s
  /** Return the 65-byte uncompressed SEC1 P-256 public key (`0x04 || x || y`). */
  publicKey(): Uint8Array | Promise<Uint8Array>;               // 65 bytes: 0x04 || x || y
  /** Return the RFC 7638 EC JWK thumbprint as unpadded base64url. */
  thumbprint(): string | Promise<string>;                      // RFC 7638 EC, base64url
  /** Return a key identifier and public key in one atomic snapshot; required for anchors and key transitions. */
  keyIdentity?(): {
    /** A non-empty key identifier. */
    keyId: string;
    /** The 65-byte uncompressed SEC1 P-256 public key. */
    publicKey: Uint8Array
  } | Promise<{
    /** A non-empty key identifier. */
    keyId: string;
    /** The 65-byte uncompressed SEC1 P-256 public key. */
    publicKey: Uint8Array
  }>;
  /** Return role, key identifier, and public key atomically; grant signing requires the issuer role. */
  signingIdentity?(): Promise<AtomicSigningIdentity> | AtomicSigningIdentity;
}

/** A telemetry event from a v3 signer, passed to {@link V3SignOpts.onEvent}. */
export interface V3SignerEvent {
  /** The signing operation that emitted this event. */
  readonly kind: "v3_report" | "v3_anchor" | "v3_grant" | "v3_key_transition";
  /** One start event, followed by one stop on success or error on failure. */
  readonly phase: "start" | "stop" | "error";
}

/** Options for the v3 signers: the same fields and defaults as `SignOpts`, with v3 event kinds. */
export interface V3SignOpts {
  /** Size limits passed to the v3 producers and assembler. */
  readonly bounds?: Bounds;
  /** The proof's `iat` in Unix seconds (`signV3Report`). Default: the wall clock. */
  readonly issuedAt?: number;
  /** The proof's `jti` (`signV3Report`). Default: `crypto.randomUUID()`; where that is absent, `producer_error`. */
  readonly proofId?: string;
  /** The anchor timestamp in Unix seconds (`signV3Anchor`). Default: the wall clock. */
  readonly anchoredAt?: number;
  /** Called with a start event and then a stop or error event. A listener that throws is ignored. */
  readonly onEvent?: (event: V3SignerEvent) => void;
}

/** The request a v3 holder proof binds (`signV3Report`); the fields mean what they mean in `ReportInput`. */
export interface V3ReportInput {
  /** The signed grant as ASCII compact JWS bytes; included unchanged in the returned envelope. */
  readonly grantCompact: Uint8Array;
  /** The operation name to bind; the resource must match it against a permitted grant operation. */
  readonly operation: string;
  /** The HTTP request method, such as "POST". */
  readonly method: string;
  /** The absolute HTTPS request URI; URI normalization follows the wire profile. */
  readonly targetUri: string;
  /** A lowercase RFC 4122 UUID identifying one logical invocation; the host runtime reserves it for single use. */
  readonly invocationId: string;
  /** Typed request arguments whose canonical projection is committed to by the proof digest. */
  readonly castArguments: Tagged;
  /** Optional server-issued nonce to bind into the proof. */
  readonly nonce?: string;
}

/** A v3 boundary anchor (`signV3Anchor`); the fields mean what they mean in `AnchorInput`. */
export interface V3AnchorInput {
  /** A non-empty identifier for this boundary anchor. */
  readonly anchorId: string;
  /** A non-empty identifier for the consumption chain. */
  readonly chainId: string;
  /** The covered chain sequence number, a non-negative integer. */
  readonly sequence: number;
  /** The chain hash at the covered sequence, exactly 32 bytes. */
  readonly chainHash: Uint8Array; // 32 bytes
}

/** A v3 capability grant (`signV3Grant`); the fields mean what they mean in `GrantInput`, with the v2 selector kinds and an EC holder thumbprint. */
export interface V3GrantInput {
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
  /** The holder’s RFC 7638 EC JWK thumbprint as unpadded base64url. */
  readonly holderThumbprint: string; // RFC 7638 EC thumbprint, base64url
  /** At least one operation and its argument selectors; granting these bounds does not replace host authorization policy. */
  readonly operations: readonly V3OperationInput[];
}

/** A v3 key transition (`signV3KeyTransition`); `nextPublicKey` is a 65-byte uncompressed P-256 point. */
export interface V3TransitionInput {
  /** A non-empty identifier for the key transition. */
  readonly transitionId: string;
  /** A non-empty identifier for the consumption chain. */
  readonly chainId: string;
  /** The next key activation time in integer Unix seconds. */
  readonly effectiveAt: number;
  /** The next key’s non-empty identifier. */
  readonly nextKeyId: string;
  /** The next key’s 65-byte uncompressed SEC1 P-256 point (`0x04 || x || y`). */
  readonly nextPublicKey: Uint8Array; // 65 bytes: 0x04 || x || y
}

const nowSeconds = () => Math.floor(Date.now() / 1000);
const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isU8 = (v: unknown, n?: number): v is Uint8Array => v instanceof Uint8Array && (n === undefined || v.length === n);

// --- handle resolvers: the v1 resolvers (one try, a private copy of the key, a fresh snapshot object)
// with the suite's 65-byte uncompressed-SEC1 width -----------------------------------------------

// A handle's P-256 public key must be the 65-byte uncompressed SEC1 point (0x04 || x || y) with x, y < p
// on the curve: refused here, at resolution, before sign() is ever called, matching Ed25519's resolution
// check (handle.ts ed25519Key). es256VerifyStrict re-validates the key at every signature.
const p256Key: KeyCheck = (key) => key.length === 65 && key[0] === 0x04 && isOnCurveP256(key.subarray(1, 33), key.subarray(33));
type Es256KeyIdentity = { keyId: string; publicKey: Uint8Array };

const resolveEs256PublicKey = (handle: Es256KeyHandle): Promise<Uint8Array | undefined> => resolveKeyWith(() => handle.publicKey(), p256Key);
const resolveEs256KeyIdentity = (handle: Es256KeyHandle): Promise<Es256KeyIdentity | undefined> => resolveIdentityWith(() => handle.keyIdentity?.(), p256Key);
/** The issuer-role gate, ES256 form: grants require an issuer-role identity resolved atomically. */
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

/**
 * Sign a contract-major-3 (ES256) holder proof. The signature is normalized to low-S and verified
 * strictly against the handle's public key before assembly.
 *
 * @returns `{ ok: true, value: { grant, proof } }`, or `invalid_report`, `invalid_key_handle`
 *   (including a public key that is not an uncompressed point on P-256), `producer_error` or `signing_failed`.
 * @example https://github.com/baselabs/bounded_authority_signer_typescript#contract-major-3-es256
 */
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

/**
 * Sign a contract-major-3 (ES256) boundary anchor. Needs `handle.keyIdentity()`.
 *
 * @returns `{ ok: true, value: { anchor } }`, or `invalid_anchor`, `invalid_key_handle`, `producer_error` or `signing_failed`.
 * @example https://github.com/baselabs/bounded_authority_signer_typescript#contract-major-3-es256
 */
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

/**
 * Sign a contract-major-3 (ES256) capability grant. Issuer-only: the issuer-role gate of `signGrant` applies.
 *
 * @returns `{ ok: true, value: { grant } }`, or `invalid_grant`, `invalid_key_handle`, `producer_error` or `signing_failed`.
 * @example https://github.com/baselabs/bounded_authority_signer_typescript#contract-major-3-es256
 */
export async function signV3Grant(input: V3GrantInput, handle: Es256KeyHandle, opts: V3SignOpts = {}): Promise<SignerResult<GrantCompact>> {
  const emit = emitter(opts, "v3_grant");
  emit("start");
  if (!isStr(input?.issuer) || !isStr(input?.grantId) || !Array.isArray(input?.audiences) ||
      ![input?.issuedAt, input?.notBefore, input?.expiresAt].every(Number.isInteger) ||
      !isStr(input?.holderThumbprint) || !Array.isArray(input?.operations)) {
    emit("error");
    return err("invalid_grant");
  }
  // The issuer-role gate (ES256 form): only an issuer-role identity (resolved
  // atomically) may sign a grant. A holder handle fails closed BEFORE
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

/**
 * Sign a contract-major-3 (ES256) key transition. Needs `handle.keyIdentity()`; `nextPublicKey` is 65 bytes.
 *
 * @returns `{ ok: true, value: { keyTransition } }`, or `invalid_transition`, `invalid_key_handle`, `producer_error` or `signing_failed`.
 * @example https://github.com/baselabs/bounded_authority_signer_typescript#contract-major-3-es256
 */
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
