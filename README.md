# @bounded-authority-protocol/signer

[![npm](https://img.shields.io/npm/v/@bounded-authority-protocol/signer)](https://www.npmjs.com/package/@bounded-authority-protocol/signer)
[![CI](https://github.com/baselabs/bounded_authority_signer_typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/baselabs/bounded_authority_signer_typescript/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

The holder/issuer companion **signer** for the Bounded Authority Protocol in TypeScript —
the port of the Elixir
[`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter).

The protocol's verifier package produces each object's deterministic signing input and
**refuses to sign**. This library takes a caller-owned key handle and a report and produces
the signed compact form. **The private key never enters the library**: callers supply a
handle whose methods reach their own custody — an HSM, a KMS, or an in-process key in tests.
Every handle method may be async; remote custodians are first-class.

It signs; [`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
verifies. It is not a decision maker, not a transport, and not the authority runtime.

## Install

```bash
npm install @bounded-authority-protocol/signer
```

Requires Node.js `>= 22`. One runtime dependency: the verifier package.

## The five signers

| Function | Object | Role |
|---|---|---|
| `signReport` | holder proof (the grant passes through untouched) | holder |
| `signLocalLoopbackReport` | local-loopback application proof (`ba+loopback-proof`) | holder |
| `signAnchor` | boundary anchor | role-agnostic |
| `signKeyTransition` | key transition | role-agnostic |
| `signGrant` | grant | issuer-only, structurally gated |

Every result is `{ ok: true, value }` or `{ ok: false, error }` with a closed error-code set
(`invalid_report`, `invalid_anchor`, `invalid_grant`, `invalid_transition`,
`invalid_key_handle`, `signing_failed`, `producer_error`) — no key material, nonce values, or
report content ever appears in an error.

## Quickstart — an edge agent proves a request

```ts
import { signGrant, signReport } from "@bounded-authority-protocol/signer";

// Issuer side: an issuer-role handle signs the capability grant.
const { grant } = (await signGrant(
  {
    issuer: "https://issuer.example.test",
    grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"],
    issuedAt: 1_731_728_000, notBefore: 1_731_728_000, expiresAt: 1_731_736_000,
    holderThumbprint: holderThumbprintB64, // RFC 7638 thumbprint of the holder key
    operations: [{ name: "transfer", selectors: [{ kind: "all" }] }],
  },
  issuerHsmHandle, // { signingIdentity(): { role: "issuer", keyId, publicKey }, sign, ... }
)).value!;

// Holder side: the agent's handle signs the proof binding THIS request.
const envelope = await signReport(
  {
    grantCompact: grant, operation: "transfer", method: "POST",
    targetUri: "https://resource.example.test/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000",
    castArguments: { t: "object", v: new Map([["amount", { t: "int", v: 5000 }]]) },
  },
  holderHandle,
  { proofId: "urn:example:proof:1" },
);

// The receiver verifies with the verifier package — never trusting this library.
// checkEnvelope(envelope.grant, envelope.proof, expected) → cryptographic facts.
```

## The key-handle contract

```ts
interface KeyHandle {
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;        // 64-byte Ed25519
  publicKey(): Uint8Array | Promise<Uint8Array>;                       // 32 bytes
  thumbprint(): string | Promise<string>;                              // RFC 7638, base64url
  keyIdentity?(): { keyId, publicKey } | Promise<...>;                 // anchor + transition
  signingIdentity?(): { role: "issuer" | "holder", keyId, publicKey }; // grants
}
```

Two load-bearing rules port unchanged from the Elixir adapter:

- **The C1 gate** — `signGrant` resolves the handle's role, key id, and public key as ONE
  atomic `signingIdentity()` snapshot and fails closed before `sign()` is ever called unless
  the role is `issuer`. A holder handle can never mint its own capability.
- **The wrong-key guard** — the shared signing tail verifies every signature against the
  resolved public key *before* assembly. A handle whose `sign()` used a different key (a
  rotation race, a misconfigured custodian) fails loudly as `signing_failed`, never a silent
  false-success deferred to the verifier.

The local-loopback profile is selected by function name — never inferred: the nonce is
required, and the target must be exactly `http://127.0.0.1[:port]/…` or `http://[::1][:port]/…`
(`localhost` and every non-canonical spelling fail closed).

## Evidence

Every compact this library produces is verified in CI through the independent verifier
package (`checkEnvelope`, `verifyGrant`, `verifyHistoricalAnchor`, `verifyKeyTransition`, the
loopback profile's `checkEnvelope`) — no self-round-trip claims. The closure gates (C1 role
gate, wrong-key guard, loopback nonce and canonical-target admission, atomic-identity
requirement) are red-capable: mechanically removing the check fails its test.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
