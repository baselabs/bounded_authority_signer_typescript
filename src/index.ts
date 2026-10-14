// The public surface of @bounded-authority-protocol/signer — the TypeScript
// companion signer for the Bounded Authority Protocol (the port of the Elixir
// bounded_authority_report_adapter). This library takes a caller-owned key
// handle and a protocol signing input and produces the signed compact form;
// the private key never enters it. It signs; the @bounded-authority-protocol/
// verifier package verifies. It is not a decision maker and not a runtime.
export {
  signReport,
  signLocalLoopbackReport,
  signAnchor,
  signGrant,
  signKeyTransition,
} from "./api.js";
export type {
  ReportInput, AnchorInput, GrantInput, TransitionInput, SignOpts, SignerEvent,
  Envelope, AnchorCompact, GrantCompact, TransitionCompact,
} from "./api.js";
export {
  signV2Report,
  signV2Anchor,
  signV2Grant,
  signV2KeyTransition,
} from "./apiV2.js";
export type {
  V2ReportInput, V2AnchorInput, V2GrantInput, V2TransitionInput, V2SignOpts, V2SignerEvent,
  V2OperationInput, V2SelectorInput,
} from "./apiV2.js";
export {
  signV3Report,
  signV3Anchor,
  signV3Grant,
  signV3KeyTransition,
} from "./apiV3.js";
export type {
  V3ReportInput, V3AnchorInput, V3GrantInput, V3TransitionInput, V3SignOpts, V3SignerEvent,
  Es256KeyHandle,
} from "./apiV3.js";
export type {
  KeyHandle, KeyRole, AtomicKeyIdentity, AtomicSigningIdentity,
  SignerErrorCode, SignerResult,
} from "./handle.js";
// WebCrypto key handles (0.6.0): the existing handle types, built from a caller-owned WebCrypto key pair
// whose private key is non-extractable.
export { ed25519KeyHandle, es256KeyHandle } from "./webcrypto.js";
export type { WebCryptoKeyLike, WebCryptoKeyPairLike, WebCryptoHandleOptions } from "./webcrypto.js";
