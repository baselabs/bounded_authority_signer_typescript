// The contract-major 3 producing profile (`BAP3-ES256-SHA256`, ADR 0035 /
// spec/bap-v3.md): the deterministic signing-input composers for the ES256
// suite. The producing side lives in this module — composed to mirror the
// verifier package's v2 producer structure with exactly the v3 deltas the spec
// names: `alg: "ES256"` in every protected header, payload `v: 3`, the
// `BAP3-REQUEST\0` digest prefix, the EC proof JWK `{crv, kty, x, y}`, the RFC
// 7638 EC thumbprint, and 65-byte uncompressed-SEC1 raw public keys. The
// verifier package's 0.3.0 release ships its own v3 verify surface; delegating
// composition to the verifier's v3 producers remains a recorded, owner-gated
// switch.
//
// Version-neutral algebra (JCS, JSON, base64url, SHA-256, typed projection,
// URI normalization, Bounds) single-sources from the verifier package's
// exported primitives — the same source the v1 flow composes through — so the
// only bytes authored here are the v3-specific ones. Pure and deterministic:
// no clock, no randomness, no network (times and keys are inputs).
import {
  base64urlDecode,
  base64urlEncode,
  jcsEncode,
  jsonDecode,
  MAXIMA,
  MAXIMUM_BOUNDS,
  sha256,
  strUtf8,
  typedProject,
  uriNormalize,
  utf8Str,
  type Bounds,
  type MaximaKey,
  type Result,
  type Tagged,
} from "@bounded-authority-protocol/verifier";
import { fail, trying } from "@bounded-authority-protocol/verifier";

const ALG = "ES256";
const GRANT_TYP = "ba+cap";
const PROOF_TYP = "dpop+jwt";
const ANCHOR_TYP = "ba+chain-anchor";
const TRANSITION_TYP = "ba+key-transition";
const VERSION = 3;

// `BAP3-REQUEST\0` — the v3 request-digest domain separator (spec/bap-v3.md §2;
// REQ3-SIGNING-digest-prefix). Exact ASCII including the final zero byte.
export const V3_REQUEST_PREFIX = new Uint8Array([
  0x42, 0x41, 0x50, 0x33, 0x2d, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x00, // "BAP3-REQUEST\0"
]);

// The suite fixed widths (spec/bap-v3.md §5; REQ3-BOUNDS-fixed-widths) —
// immutable cryptographic constants of `BAP3-ES256-SHA256`, deliberately NOT
// read from the shared Bounds row (whose `public_key_bytes: 32` stays inert
// for v3 — no v3 code reads it as a width).
export const P256_COORDINATE_BYTES = 32;
export const RAW_PUBLIC_KEY_BYTES = 65;   // 0x04 || x || y (uncompressed SEC1)
export const RAW_SIGNATURE_BYTES = 64;    // r || s, fixed-width 32 each

// The all-zero 32-byte hash: sequence-0 anchor chain hash (the v1 genesis rule
// incorporated unchanged).
const DEFAULT_HASH = new Uint8Array(32);
const DOT = 0x2e;

// ---------------------------------------------------------------------------
// Bounds (the shared v1 Bounds contract, guarded exactly as the verifier's
// producers guard it: tighten-only, fixed-width keys identity-only).

const FIXED_WIDTH_KEYS: ReadonlySet<MaximaKey> = new Set([
  "digest_bytes",
  "public_key_bytes",
  "signature_bytes",
]);

function guardBounds(b: Bounds): Bounds {
  for (const [key, value] of b.overrides) {
    if (!Number.isInteger(value)) fail(`v3 bounds: non-integer limit ${key}`);
    if (FIXED_WIDTH_KEYS.has(key)) {
      if (value !== MAXIMA[key]) fail(`v3 bounds: fixed-width key ${key} must equal maximum`);
    } else {
      if (value <= 0) fail(`v3 bounds: non-positive limit ${key}`);
      if (value > MAXIMA[key]) fail(`v3 bounds: widening limit ${key}`);
    }
  }
  return b;
}

const resolveBound = (b: Bounds, key: MaximaKey): number => b.overrides.get(key) ?? MAXIMA[key];

// ---------------------------------------------------------------------------
// Claim-shape validators (the v1/v2 forms, ported so the composers stand
// alone; the verifier package does not export these).

function isWellFormed(s: string): boolean {
  const anyStr = s as string & { isWellFormed?: () => boolean };
  return typeof anyStr.isWellFormed === "function"
    ? anyStr.isWellFormed()
    : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

// StringOrURI (RFC 7519 §2): bare strings pass; a scheme is required to be
// valid and the remainder to be uri_bytes-shaped, with a `//` authority
// structurally validated.
function isStringOrUri(s: string): boolean {
  if (!isWellFormed(s)) return false;
  const colon = s.indexOf(":");
  if (colon === -1) return true;
  const scheme = s.slice(0, colon);
  if (!/^[A-Za-z][A-Za-z0-9+\-.]*$/.test(scheme)) return false;
  if (!/^(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=])*$/.test(s)) return false;
  const rest = s.slice(colon + 1);
  if (!rest.startsWith("//")) return true;
  return validUriAuthority(rest.slice(2).split(/[/?#]/, 1)[0] ?? "");
}

function validUriAuthority(authority: string): boolean {
  const at = authority.indexOf("@");
  const hostport = at === -1 ? authority : authority.slice(at + 1);
  if (hostport.includes("@")) return false;
  if (hostport.startsWith("[")) {
    const close = hostport.indexOf("]");
    if (close === -1) return false;
    if (!/^[0-9A-Fa-f:.]+$/.test(hostport.slice(1, close))) return false;
    const suffix = hostport.slice(close + 1);
    return suffix === "" || /^:\d*$/.test(suffix);
  }
  if (hostport.includes("[") || hostport.includes("]")) return false;
  if ((hostport.match(/:/g) ?? []).length > 1) return false;
  const sep = hostport.lastIndexOf(":");
  return sep === -1 || /^\d*$/.test(hostport.slice(sep + 1));
}

// Lowercase RFC 4122 UUID.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// ---------------------------------------------------------------------------
// The EC JWK and the RFC 7638 EC thumbprint (spec/bap-v3.md §3.1).

export interface EcPublicJwk {
  readonly crv: "P-256";
  readonly kty: "EC";
  readonly x: string; // canonical unpadded base64url, 32 bytes
  readonly y: string;
}

// NIST P-256 domain parameters (SEC 2) — pure arithmetic, no backend.
const P256_PRIME = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

/** The on-curve check the profile owns (REQ3-KEY-point-on-curve): y² ≡ x³ − 3x + b (mod p), 0 ≤ x,y < p. */
export function isOnCurveP256(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length !== P256_COORDINATE_BYTES || y.length !== P256_COORDINATE_BYTES) return false;
  let bx = 0n;
  let by = 0n;
  for (const byte of x) bx = (bx << 8n) | BigInt(byte);
  for (const byte of y) by = (by << 8n) | BigInt(byte);
  if (bx >= P256_PRIME || by >= P256_PRIME) return false;
  const lhs = (by * by) % P256_PRIME;
  const rhs = (bx * bx * bx + (P256_PRIME - 3n) * bx + P256_B) % P256_PRIME;
  return lhs === rhs;
}

/** The 65-byte uncompressed SEC1 point `0x04 || x || y` → the EC JWK (REQ3-KEY-uncompressed-sec1; REQ3-HEADER-proof-jwk). */
export function ecJwkFromRawPublicKey(raw: Uint8Array): EcPublicJwk {
  if (raw.length !== RAW_PUBLIC_KEY_BYTES || raw[0] !== 0x04)
    fail("v3 ec_jwk: uncompressed SEC1 point");
  const x = raw.subarray(1, 1 + P256_COORDINATE_BYTES);
  const y = raw.subarray(1 + P256_COORDINATE_BYTES, RAW_PUBLIC_KEY_BYTES);
  if (!isOnCurveP256(x, y)) fail("v3 ec_jwk: point not on P-256");
  return {
    crv: "P-256",
    kty: "EC",
    x: utf8Str(base64urlEncode(x)),
    y: utf8Str(base64urlEncode(y)),
  };
}

// The RFC 7638 preimage over exactly the four required EC members in
// lexicographic order (REQ3-HEADER-thumbprint).
export function ecThumbprintPreimage(raw: Uint8Array): Uint8Array {
  const jwk = ecJwkFromRawPublicKey(raw);
  const members = new Map<string, Tagged>([
    ["crv", { t: "string", v: strUtf8(jwk.crv) }],
    ["kty", { t: "string", v: strUtf8(jwk.kty) }],
    ["x", { t: "string", v: strUtf8(jwk.x) }],
    ["y", { t: "string", v: strUtf8(jwk.y) }],
  ]);
  return jcsEncode({ t: "object", v: members }, MAXIMUM_BOUNDS);
}

/** RFC 7638 EC thumbprint, raw 32-byte digest. */
export function ecThumbprintRaw(raw: Uint8Array): Uint8Array {
  return sha256(ecThumbprintPreimage(raw));
}

/** RFC 7638 EC thumbprint, unpadded base64url — the `cnf.jkt` spelling. */
export function ecThumbprint(raw: Uint8Array): string {
  return utf8Str(base64urlEncode(ecThumbprintRaw(raw)));
}

// ---------------------------------------------------------------------------
// The v3 request digest: SHA-256("BAP3-REQUEST\0" || JCS([operation, typed(cast_arguments)])).

function withinTaggedBounds(v: Tagged, level: number, b: Bounds): boolean {
  switch (v.t) {
    case "null":
    case "bool":
      return level <= resolveBound(b, "depth");
    case "int":
      return level <= resolveBound(b, "depth") && Math.abs(v.v) <= resolveBound(b, "integer_magnitude");
    case "float":
      return level <= resolveBound(b, "depth") && Number.isFinite(v.v) && Math.abs(v.v) <= resolveBound(b, "float_magnitude");
    case "string":
      return level <= resolveBound(b, "depth") && v.v.length <= resolveBound(b, "string_bytes");
    case "array":
      return level < resolveBound(b, "depth")
        && v.v.length <= resolveBound(b, "array_items")
        && v.v.every((item) => withinTaggedBounds(item, level + 1, b));
    case "object":
      return level < resolveBound(b, "depth")
        && v.v.size <= resolveBound(b, "object_members")
        && [...v.v.values()].every((val) => withinTaggedBounds(val, level + 1, b));
  }
}

function countTaggedNodes(v: Tagged): number {
  switch (v.t) {
    case "array": return 1 + v.v.reduce((n, item) => n + countTaggedNodes(item), 0);
    case "object": return 1 + [...v.v.values()].reduce((n, val) => n + countTaggedNodes(val), 0);
    default: return 1;
  }
}

export function v3RequestDigest(operation: string, castArguments: Tagged, bounds?: Bounds): Uint8Array {
  const b = guardBounds(bounds ?? MAXIMUM_BOUNDS);
  const opBytes = strUtf8(operation);
  if (opBytes.length < 1 || opBytes.length > resolveBound(b, "operation_bytes"))
    fail("v3 request_digest: operation bound");
  for (const byte of opBytes) {
    if (byte < 0x20 || byte > 0x7e) fail("v3 request_digest: operation printable ASCII");
  }
  const projected = typedProject(castArguments);
  const array: Tagged = { t: "array", v: [{ t: "string", v: opBytes }, projected] };
  if (!withinTaggedBounds(array, 0, b)) fail("v3 request_digest: cast_arguments bounds");
  if (countTaggedNodes(array) > resolveBound(b, "total_nodes")) fail("v3 request_digest: total_nodes");
  const jcs = jcsEncode(array, b);
  if (jcs.length > resolveBound(b, "jcs_bytes")) fail("v3 request_digest: jcs_bytes bound");
  return sha256(V3_REQUEST_PREFIX, jcs);
}

// ---------------------------------------------------------------------------
// Producer types.

export type V3SelectorInput =
  | "all"
  | { readonly kind: "all" }
  | { readonly kind: "equals"; readonly path: readonly string[]; readonly value: Tagged }
  | { readonly kind: "one_of"; readonly path: readonly string[]; readonly values: readonly Tagged[] }
  | { readonly kind: "lte"; readonly path: readonly string[]; readonly value: Tagged }
  | { readonly kind: "gte"; readonly path: readonly string[]; readonly value: Tagged };

export interface V3OperationInput {
  readonly name: string;
  readonly selectors: readonly V3SelectorInput[];
}

export interface GrantProducerV3 {
  readonly keyId: string;
  readonly issuer: string;
  readonly grantId: string;
  readonly audiences: readonly string[];
  readonly issuedAt: number;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly holderThumbprint: string;
  readonly operations: readonly V3OperationInput[];
}

export interface ProofProducerV3 {
  readonly holderPublicKey: Uint8Array; // 65-byte uncompressed SEC1
  readonly proofId: string;
  readonly method: string;
  readonly targetUri: string;
  readonly issuedAt: number;
  readonly invocationId: string;
  readonly operation: string;
  readonly grantCompact: Uint8Array;
  readonly castArguments: Tagged;
  readonly nonce?: string;
}

export interface BoundaryAnchorProducerV3 {
  readonly anchorId: string;
  readonly anchoredAt: number;
  readonly chainId: string;
  readonly sequence: number;
  readonly chainHash: Uint8Array; // 32 bytes
  readonly keyId: string;
  readonly publicKey: Uint8Array; // 65-byte uncompressed SEC1
}

export interface KeyTransitionProducerV3 {
  readonly transitionId: string;
  readonly chainId: string;
  readonly effectiveAt: number;
  readonly currentKeyId: string;
  readonly currentPublicKey: Uint8Array; // 65 bytes
  readonly nextKeyId: string;
  readonly nextPublicKey: Uint8Array; // 65 bytes
}

export type V3SigningInputKind = "grant" | "proof" | "boundary_anchor" | "key_transition";

export interface V3SigningInput {
  readonly kind: V3SigningInputKind;
  readonly protectedSegment: Uint8Array; // ASCII base64url text
  readonly payloadSegment: Uint8Array; // ASCII base64url text
}

const isStr = (v: unknown): v is string => typeof v === "string";
const isU8 = (v: unknown): v is Uint8Array => v instanceof Uint8Array;

function taggedHeader(members: ReadonlyMap<string, Tagged>, b: Bounds): Uint8Array {
  return strUtf8(utf8Str(base64urlEncode(jcsEncode({ t: "object", v: members }, b))));
}

// ---------------------------------------------------------------------------
// Selectors (the five-kind v2/v3 algebra: all, equals, one_of, lte, gte — the
// range bounds must be numeric-tagged before they can be minted).

function selectorToTagged(s: V3SelectorInput, b: Bounds): Tagged {
  if (s === "all" || (typeof s === "object" && s.kind === "all")) {
    return { t: "object", v: new Map([["kind", { t: "string", v: strUtf8("all") }]]) };
  }
  if (typeof s === "object" && s.kind === "equals") {
    const path = validatePath(s.path, b);
    validateSelectorValue(s.value, b);
    return { t: "object", v: new Map<string, Tagged>([
      ["kind", { t: "string", v: strUtf8("equals") }],
      ["path", path],
      ["value", s.value],
    ]) };
  }
  if (typeof s === "object" && s.kind === "one_of") {
    const path = validatePath(s.path, b);
    if (s.values.length < 1 || s.values.length > resolveBound(b, "one_of_values"))
      fail("v3 selector: values count");
    for (const v of s.values) validateSelectorValue(v, b);
    return { t: "object", v: new Map<string, Tagged>([
      ["kind", { t: "string", v: strUtf8("one_of") }],
      ["path", path],
      ["values", { t: "array", v: [...s.values] }],
    ]) };
  }
  if (typeof s === "object" && (s.kind === "lte" || s.kind === "gte")) {
    const path = validatePath(s.path, b);
    if (s.value.t !== "int" && s.value.t !== "float") fail("v3 selector: numeric bound");
    validateSelectorValue(s.value, b);
    return { t: "object", v: new Map<string, Tagged>([
      ["kind", { t: "string", v: strUtf8(s.kind) }],
      ["path", path],
      ["value", s.value],
    ]) };
  }
  fail("v3 selector: shape");
}

function validatePath(path: readonly string[], b: Bounds): Tagged {
  if (path.length < 1 || path.length > resolveBound(b, "path_segments"))
    fail("v3 selector: path length");
  const segs: Tagged[] = [];
  for (const seg of path) {
    const sb = strUtf8(seg);
    if (sb.length < 1 || sb.length > resolveBound(b, "key_bytes"))
      fail("v3 selector: path segment bytes");
    segs.push({ t: "string", v: sb });
  }
  return { t: "array", v: segs };
}

function validateSelectorValue(v: Tagged, b: Bounds): void {
  checkNode(v, 1, b);
}

function checkNode(v: Tagged, depth: number, b: Bounds): void {
  if (depth > resolveBound(b, "depth")) fail("v3 selector: value depth");
  switch (v.t) {
    case "string":
      if (v.v.length > resolveBound(b, "string_bytes")) fail("v3 selector: string bytes");
      return;
    case "int":
      if (Math.abs(v.v) > resolveBound(b, "integer_magnitude")) fail("v3 selector: int magnitude");
      return;
    case "float":
      if (Math.abs(v.v) > resolveBound(b, "float_magnitude")) fail("v3 selector: float magnitude");
      return;
    case "array": {
      if (v.v.length > resolveBound(b, "array_items")) fail("v3 selector: array items");
      for (const item of v.v) checkNode(item, depth + 1, b);
      return;
    }
    case "object": {
      if (v.v.size > resolveBound(b, "object_members")) fail("v3 selector: object members");
      for (const [, val] of v.v) checkNode(val, depth + 1, b);
      return;
    }
    default: return;
  }
}

// ---------------------------------------------------------------------------
// 1. grant_signing_input.

export function grantSigningInput(grant: GrantProducerV3, bounds?: Bounds): Result<V3SigningInput> {
  return trying(() => {
    if (grant === null || typeof grant !== "object") fail("v3 grant_signing_input: object");
    const b = guardBounds(bounds ?? MAXIMUM_BOUNDS);
    if (!isStr(grant.keyId)) fail("v3 grant_signing_input: key_id");
    const keyIdBytes = strUtf8(grant.keyId);
    if (keyIdBytes.length < 1 || keyIdBytes.length > resolveBound(b, "kid_bytes"))
      fail("v3 grant_signing_input: key_id bytes");
    if (!/^[A-Za-z0-9._~-]+$/.test(grant.keyId)) fail("v3 grant_signing_input: key_id charset");
    if (!isStr(grant.issuer) || !isStringOrUri(grant.issuer)) fail("v3 grant_signing_input: issuer");
    if (!isStr(grant.grantId) || !isStringOrUri(grant.grantId)) fail("v3 grant_signing_input: grant_id");
    if (!Array.isArray(grant.audiences) || grant.audiences.length < 1 || grant.audiences.length > resolveBound(b, "audiences"))
      fail("v3 grant_signing_input: audiences count");
    for (const a of grant.audiences) {
      if (!isStr(a)) fail("v3 grant_signing_input: audience string-or-uri");
      const ab = strUtf8(a);
      if (ab.length < 1 || ab.length > resolveBound(b, "identifier_bytes"))
        fail("v3 grant_signing_input: audience bytes");
      if (!isStringOrUri(a)) fail("v3 grant_signing_input: audience string-or-uri");
    }
    if (![grant.issuedAt, grant.notBefore, grant.expiresAt].every(Number.isInteger))
      fail("v3 grant_signing_input: integer times");
    if (!isStr(grant.holderThumbprint)) fail("v3 grant_signing_input: holder_thumbprint");
    if (base64urlDecode(strUtf8(grant.holderThumbprint)).length !== 32)
      fail("v3 grant_signing_input: holder_thumbprint width");
    if (!Array.isArray(grant.operations) || grant.operations.length < 1 || grant.operations.length > resolveBound(b, "operations"))
      fail("v3 grant_signing_input: operations count");
    const header = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["kid", { t: "string", v: keyIdBytes }],
      ["typ", { t: "string", v: strUtf8(GRANT_TYP) }],
    ]);
    const payload = buildGrantPayload(grant, b);
    return {
      kind: "grant" as const,
      protectedSegment: taggedHeader(header, b),
      payloadSegment: taggedHeader(payload, b),
    };
  });
}

function buildGrantPayload(grant: GrantProducerV3, b: Bounds): Map<string, Tagged> {
  const audMembers = grant.audiences.map((a) => ({ t: "string", v: strUtf8(a) }) as Tagged);
  const opsMembers = grant.operations.map((op) => {
    if (op === null || typeof op !== "object" || !isStr(op.name) || !Array.isArray(op.selectors))
      fail("v3 grant_signing_input: operation shape");
    const nameBytes = strUtf8(op.name);
    if (nameBytes.length < 1 || nameBytes.length > resolveBound(b, "operation_bytes"))
      fail("v3 grant_signing_input: operation name bytes");
    if (!/^[\x20-\x7e]+$/.test(op.name)) fail("v3 grant_signing_input: operation name charset");
    if (op.selectors.length < 1 || op.selectors.length > resolveBound(b, "selectors"))
      fail("v3 grant_signing_input: selectors count");
    return { t: "object", v: new Map<string, Tagged>([
      ["name", { t: "string", v: nameBytes }],
      ["selectors", { t: "array", v: op.selectors.map((s) => selectorToTagged(s, b)) }],
    ]) } as Tagged;
  });
  const cnfMembers = new Map<string, Tagged>([["jkt", { t: "string", v: strUtf8(grant.holderThumbprint) }]]);
  return new Map<string, Tagged>([
    ["aud", { t: "array", v: audMembers }],
    ["cnf", { t: "object", v: cnfMembers }],
    ["exp", { t: "int", v: grant.expiresAt }],
    ["iat", { t: "int", v: grant.issuedAt }],
    ["iss", { t: "string", v: strUtf8(grant.issuer) }],
    ["jti", { t: "string", v: strUtf8(grant.grantId) }],
    ["nbf", { t: "int", v: grant.notBefore }],
    ["operations", { t: "array", v: opsMembers }],
    ["v", { t: "int", v: VERSION }],
  ]);
}

// ---------------------------------------------------------------------------
// 2. proof_signing_input (the standard profile only — the local-loopback
// application proof profile is contract-major-1-bound and exposes no v3 form).

export function proofSigningInput(proof: ProofProducerV3, bounds?: Bounds): Result<V3SigningInput> {
  return trying(() => {
    if (proof === null || typeof proof !== "object") fail("v3 proof_signing_input: object");
    const b = guardBounds(bounds ?? MAXIMUM_BOUNDS);
    if (!isU8(proof.holderPublicKey)) fail("v3 proof_signing_input: holder key");
    const jwk = ecJwkFromRawPublicKey(proof.holderPublicKey);
    if (!isStr(proof.proofId) || !isStringOrUri(proof.proofId)) fail("v3 proof_signing_input: proof_id");
    const proofIdBytes = strUtf8(proof.proofId);
    if (!isStr(proof.method)) fail("v3 proof_signing_input: method");
    const methodBytes = strUtf8(proof.method);
    if (methodBytes.length < 1 || methodBytes.length > resolveBound(b, "method_bytes"))
      fail("v3 proof_signing_input: method bytes");
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(proof.method)) fail("v3 proof_signing_input: method token");
    if (!isStr(proof.targetUri)) fail("v3 proof_signing_input: htu");
    const htuNorm = uriNormalize(strUtf8(proof.targetUri), b);
    if (!htuNorm.ok || utf8Str(htuNorm.value) !== proof.targetUri)
      fail("v3 proof_signing_input: htu pre-normalized");
    if (!Number.isInteger(proof.issuedAt)) fail("v3 proof_signing_input: integer iat");
    if (!isStr(proof.invocationId) || !UUID_RE.test(proof.invocationId))
      fail("v3 proof_signing_input: invocation_id");
    if (!isStr(proof.operation)) fail("v3 proof_signing_input: operation");
    const opBytes = strUtf8(proof.operation);
    if (opBytes.length < 1 || opBytes.length > resolveBound(b, "operation_bytes"))
      fail("v3 proof_signing_input: operation bytes");
    if (!/^[\x20-\x7e]+$/.test(proof.operation)) fail("v3 proof_signing_input: operation charset");
    if (proof.nonce !== undefined) {
      if (!isStr(proof.nonce) || !isWellFormed(proof.nonce)) fail("v3 proof_signing_input: nonce well-formed");
      const nb = strUtf8(proof.nonce);
      if (nb.length < 1 || nb.length > resolveBound(b, "nonce_bytes")) fail("v3 proof_signing_input: nonce bytes");
    }
    const headerMembers = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["jwk", { t: "object", v: new Map<string, Tagged>([
        ["crv", { t: "string", v: strUtf8(jwk.crv) }],
        ["kty", { t: "string", v: strUtf8(jwk.kty) }],
        ["x", { t: "string", v: strUtf8(jwk.x) }],
        ["y", { t: "string", v: strUtf8(jwk.y) }],
      ]) }],
      ["typ", { t: "string", v: strUtf8(PROOF_TYP) }],
    ]);
    // Producer ath: gate the grant compact by shape+size before hashing it
    // into `ath` (the v1 scan-then-hash discipline, incorporated).
    if (!isU8(proof.grantCompact)) fail("v3 proof_signing_input: grant compact");
    scanCompactShape(proof.grantCompact, b);
    const athRaw = sha256(proof.grantCompact);
    const baReqRaw = v3RequestDigest(proof.operation, proof.castArguments, b);
    const payloadMembers = new Map<string, Tagged>([
      ["ath", { t: "string", v: strUtf8(utf8Str(base64urlEncode(athRaw))) }],
      ["ba_inv", { t: "string", v: strUtf8(proof.invocationId) }],
      ["ba_op", { t: "string", v: opBytes }],
      ["ba_req", { t: "string", v: strUtf8(utf8Str(base64urlEncode(baReqRaw))) }],
      ["htm", { t: "string", v: methodBytes }],
      ["htu", { t: "string", v: strUtf8(proof.targetUri) }],
      ["iat", { t: "int", v: proof.issuedAt }],
      ["jti", { t: "string", v: proofIdBytes }],
      ["v", { t: "int", v: VERSION }],
    ]);
    if (proof.nonce !== undefined)
      payloadMembers.set("nonce", { t: "string", v: strUtf8(proof.nonce) });
    return {
      kind: "proof" as const,
      protectedSegment: taggedHeader(headerMembers, b),
      payloadSegment: taggedHeader(payloadMembers, b),
    };
  });
}

// The shape+size scan over a candidate compact (the v1 CompactJws.scan port):
// exactly three non-empty dot-separated segments within bounds; canonicity is
// the verifier's job — this gate only refuses to hash obvious non-compacts.
function scanCompactShape(input: Uint8Array, b: Bounds): void {
  if (input.length > resolveBound(b, "compact_bytes")) fail("v3 scan_compact: byte bound");
  if (input.length === 0) fail("v3 scan_compact: empty");
  let d0 = -1;
  let d1 = -1;
  let dots = 0;
  for (let i = 0; i < input.length; i++) {
    if (input[i] === DOT) {
      if (dots === 0) d0 = i;
      else if (dots === 1) d1 = i;
      dots++;
    }
  }
  if (dots !== 2) fail("v3 scan_compact: three segments");
  if (d0 === 0 || d1 === d0 + 1 || d1 === input.length - 1) fail("v3 scan_compact: empty segment");
  const seg = resolveBound(b, "encoded_segment_bytes");
  if (d0 > seg || d1 - d0 - 1 > seg || input.length - d1 - 1 > seg)
    fail("v3 scan_compact: segment bound");
}

// ---------------------------------------------------------------------------
// 3. boundary_anchor_signing_input.

export function boundaryAnchorSigningInput(anchor: BoundaryAnchorProducerV3, bounds?: Bounds): Result<V3SigningInput> {
  return trying(() => {
    if (anchor === null || typeof anchor !== "object") fail("v3 anchor_signing_input: object");
    const b = guardBounds(bounds ?? MAXIMUM_BOUNDS);
    if (!isStr(anchor.keyId)) fail("v3 anchor_signing_input: key_id");
    const keyIdBytes = strUtf8(anchor.keyId);
    if (keyIdBytes.length < 1 || keyIdBytes.length > resolveBound(b, "kid_bytes"))
      fail("v3 anchor_signing_input: key_id bytes");
    if (!/^[A-Za-z0-9._~-]+$/.test(anchor.keyId)) fail("v3 anchor_signing_input: key_id charset");
    if (!isStr(anchor.anchorId) || !isStringOrUri(anchor.anchorId)) fail("v3 anchor_signing_input: anchor_id");
    if (!isStr(anchor.chainId) || !isStringOrUri(anchor.chainId)) fail("v3 anchor_signing_input: chain_id");
    if (!Number.isInteger(anchor.anchoredAt)) fail("v3 anchor_signing_input: integer anchored_at");
    if (!Number.isInteger(anchor.sequence) || anchor.sequence < 0) fail("v3 anchor_signing_input: non-negative sequence");
    if (!isU8(anchor.chainHash) || anchor.chainHash.length !== 32) fail("v3 anchor_signing_input: chain_hash width");
    if (!isU8(anchor.publicKey)) fail("v3 anchor_signing_input: public key");
    const fp = ecThumbprintRaw(anchor.publicKey); // validates the 65-byte on-curve form
    if (anchor.sequence === 0 && !(anchor.chainHash.every((byte, i) => byte === DEFAULT_HASH[i])))
      fail("v3 anchor_signing_input: genesis chain_hash");
    const header = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["kid", { t: "string", v: keyIdBytes }],
      ["typ", { t: "string", v: strUtf8(ANCHOR_TYP) }],
    ]);
    const payload = new Map<string, Tagged>([
      ["anchor_id", { t: "string", v: strUtf8(anchor.anchorId) }],
      ["anchored_at", { t: "int", v: anchor.anchoredAt }],
      ["chain_hash", { t: "string", v: strUtf8(utf8Str(base64urlEncode(anchor.chainHash))) }],
      ["chain_id", { t: "string", v: strUtf8(anchor.chainId) }],
      ["key_fingerprint", { t: "string", v: strUtf8(utf8Str(base64urlEncode(fp))) }],
      ["sequence", { t: "int", v: anchor.sequence }],
      ["v", { t: "int", v: VERSION }],
    ]);
    return {
      kind: "boundary_anchor" as const,
      protectedSegment: taggedHeader(header, b),
      payloadSegment: taggedHeader(payload, b),
    };
  });
}

// ---------------------------------------------------------------------------
// 4. key_transition_signing_input.

export function keyTransitionSigningInput(t: KeyTransitionProducerV3, bounds?: Bounds): Result<V3SigningInput> {
  return trying(() => {
    if (t === null || typeof t !== "object") fail("v3 transition_signing_input: object");
    const b = guardBounds(bounds ?? MAXIMUM_BOUNDS);
    if (!isU8(t.currentPublicKey) || !isU8(t.nextPublicKey)) fail("v3 transition_signing_input: key width");
    const fromFp = ecThumbprintRaw(t.currentPublicKey); // validates the 65-byte on-curve form
    const toFp = ecThumbprintRaw(t.nextPublicKey);
    if (t.currentPublicKey.every((byte, i) => byte === t.nextPublicKey[i]))
      fail("v3 transition_signing_input: distinct keys");
    if (!isStr(t.currentKeyId)) fail("v3 transition_signing_input: current_key_id");
    const currentKeyIdBytes = strUtf8(t.currentKeyId);
    if (currentKeyIdBytes.length < 1 || currentKeyIdBytes.length > resolveBound(b, "kid_bytes"))
      fail("v3 transition_signing_input: current_key_id bytes");
    if (!/^[A-Za-z0-9._~-]+$/.test(t.currentKeyId)) fail("v3 transition_signing_input: current_key_id charset");
    if (!isStr(t.nextKeyId)) fail("v3 transition_signing_input: next_key_id");
    const nextKeyIdBytes = strUtf8(t.nextKeyId);
    if (nextKeyIdBytes.length < 1 || nextKeyIdBytes.length > resolveBound(b, "kid_bytes"))
      fail("v3 transition_signing_input: next_key_id bytes");
    if (!/^[A-Za-z0-9._~-]+$/.test(t.nextKeyId)) fail("v3 transition_signing_input: next_key_id charset");
    if (!isStr(t.transitionId) || !isStringOrUri(t.transitionId)) fail("v3 transition_signing_input: transition_id");
    if (!isStr(t.chainId) || !isStringOrUri(t.chainId)) fail("v3 transition_signing_input: chain_id");
    if (!Number.isInteger(t.effectiveAt)) fail("v3 transition_signing_input: integer effective_at");
    const header = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["kid", { t: "string", v: currentKeyIdBytes }],
      ["typ", { t: "string", v: strUtf8(TRANSITION_TYP) }],
    ]);
    const payload = new Map<string, Tagged>([
      ["chain_id", { t: "string", v: strUtf8(t.chainId) }],
      ["effective_at", { t: "int", v: t.effectiveAt }],
      ["from_key_fingerprint", { t: "string", v: strUtf8(utf8Str(base64urlEncode(fromFp))) }],
      ["to_key_fingerprint", { t: "string", v: strUtf8(utf8Str(base64urlEncode(toFp))) }],
      ["to_key_id", { t: "string", v: nextKeyIdBytes }],
      ["transition_id", { t: "string", v: strUtf8(t.transitionId) }],
      ["v", { t: "int", v: VERSION }],
    ]);
    return {
      kind: "key_transition" as const,
      protectedSegment: taggedHeader(header, b),
      payloadSegment: taggedHeader(payload, b),
    };
  });
}

// ---------------------------------------------------------------------------
// 5. assemble_compact — the RFC 7515 compact form
//    `BASE64URL(protected) || "." || BASE64URL(payload) || "." || BASE64URL(signature)`,
//    then a self-check re-parse of the composed bytes (segments decode, the
//    header is the closed v3 member set with alg ES256 and the kind's typ, the
//    payload carries exactly v: 3) so the producer does not mint bytes its own
//    consumer would reject. The FULL v3 re-validation runs through the verifier
//    package's v3 surface (its 0.3.0 release), which CI cross-verifies the
//    produced compacts against; the crypto-level signature pinning in the test
//    tree stays on as byte-level composition evidence.

export function assembleCompact(input: V3SigningInput, signature: Uint8Array, bounds?: Bounds): Result<Uint8Array> {
  return trying(() => {
    const b = guardBounds(bounds ?? MAXIMUM_BOUNDS);
    if (!isU8(signature) || signature.length !== RAW_SIGNATURE_BYTES) fail("v3 assemble_compact: signature width");
    if (!isU8(input?.protectedSegment) || !isU8(input?.payloadSegment)) fail("v3 assemble_compact: segments");
    if (input.protectedSegment.length > resolveBound(b, "encoded_segment_bytes") ||
        input.payloadSegment.length > resolveBound(b, "encoded_segment_bytes"))
      fail("v3 assemble_compact: segment bound");
    const compact = concat(
      input.protectedSegment,
      new Uint8Array([DOT]),
      input.payloadSegment,
      new Uint8Array([DOT]),
      base64urlEncode(signature),
    );
    if (compact.length > resolveBound(b, "compact_bytes")) fail("v3 assemble_compact: compact_bytes");
    reparseAssembled(compact, input.kind, b);
    return compact;
  });
}

function reparseAssembled(compact: Uint8Array, kind: V3SigningInputKind, b: Bounds): void {
  scanCompactShape(compact, b);
  const dots: number[] = [];
  for (let i = 0; i < compact.length; i++) if (compact[i] === DOT) dots.push(i);
  const protectedBytes = base64urlDecode(compact.subarray(0, dots[0] ?? -1));
  const payloadBytes = base64urlDecode(compact.subarray((dots[0] ?? -1) + 1, dots[1] ?? -1));
  const header = jsonDecode(protectedBytes, b);
  if (header.t !== "object") fail("v3 assemble_compact: header object");
  const typByKind: Record<V3SigningInputKind, string> = {
    grant: GRANT_TYP,
    proof: PROOF_TYP,
    boundary_anchor: ANCHOR_TYP,
    key_transition: TRANSITION_TYP,
  };
  const alg = header.v.get("alg");
  if (alg?.t !== "string" || utf8Str(alg.v) !== ALG) fail("v3 assemble_compact: alg");
  const typ = header.v.get("typ");
  if (typ?.t !== "string" || utf8Str(typ.v) !== typByKind[kind]) fail("v3 assemble_compact: typ");
  if (kind === "grant" || kind === "boundary_anchor" || kind === "key_transition") {
    if (header.v.size !== 3 || !header.v.has("kid")) fail("v3 assemble_compact: header members");
  } else {
    if (header.v.size !== 3 || !header.v.has("jwk")) fail("v3 assemble_compact: header members");
  }
  const payload = jsonDecode(payloadBytes, b);
  if (payload.t !== "object") fail("v3 assemble_compact: payload object");
  const v = payload.v.get("v");
  if (v?.t !== "int" || v.v !== VERSION) fail("v3 assemble_compact: v");
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
