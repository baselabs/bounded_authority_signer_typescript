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
export type {
  KeyHandle, KeyRole, AtomicKeyIdentity, AtomicSigningIdentity,
  SignerErrorCode, SignerResult,
} from "./handle.js";
