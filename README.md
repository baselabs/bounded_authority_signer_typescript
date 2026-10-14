# @bounded-authority-protocol/signer

[![npm](https://img.shields.io/npm/v/@bounded-authority-protocol/signer)](https://www.npmjs.com/package/@bounded-authority-protocol/signer)
[![CI](https://github.com/baselabs/bounded_authority_signer_typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/baselabs/bounded_authority_signer_typescript/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Try it in your browser — no install:** the [envelope playground](https://baselabs.github.io/bounded_authority_signer_typescript/)
runs this package and the verifier package for real, in the page, with a key your browser
generates. For the "why" (what this adds over OAuth for MCP servers, agents, and APIs),
start at the playground's landing sections.

The holder/issuer companion **signer** for the Bounded Authority Protocol in TypeScript —
the port of the Elixir
[`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter)
([GitHub](https://github.com/baselabs/bounded_authority_report_adapter)). This package signs
**contract-major 1** (the byte-frozen v1 profile and the local-loopback profile),
**contract-major 2** (the v2 profile: `v: 2` payloads, `BAP2-*` separators and the `lte`/`gte`
range selectors, Ed25519) and **contract-major 3** (the `BAP3-ES256-SHA256` suite: ECDSA P-256
with SHA-256, low-S normalized, defined by
[ADR 0035](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0035-es256-contract-major-activation.md)).
It runs on Node.js, in browsers, in Deno and in
Bun with no Node API (see [Browsers, Deno, Bun and workers](#browsers-deno-bun-and-workers)).

The protocol's verifier package produces each object's deterministic signing input and
**refuses to sign**. This library takes a caller-owned key handle and a report and produces
the signed compact form. **The private key never enters the library**: callers supply a
handle whose methods reach their own custody — an HSM, a KMS, a non-extractable WebCrypto key
(see [WebCrypto key handles](#webcrypto-key-handles)), or an in-process key in tests. Every
handle method may be async; remote custodians are first-class.

It signs; [`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
verifies. It is not a decision maker, not a transport, and not the authority runtime.

## Install

```bash
npm install @bounded-authority-protocol/signer
```

Runs on Node.js `>= 22` (the repository develops on the pinned 22.23.1 — see
[`.tool-versions`](.tool-versions) — and runs CI on 22.23.1 and 24.19.0), current browsers,
Deno and Bun. One runtime dependency: the verifier package.

## Protocol family

- [`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
  ([GitHub](https://github.com/baselabs/bounded_authority_protocol_typescript)) — the verify
  side; this library signs, that package verifies. The dependency is one-directional (this
  signer depends on the verifier, never the reverse), and the verifier's README carries a
  worked "Pairing with the signer" example — the three-role production flow with this
  package's five signers, executed against published versions.
- [`baselabs/bounded_authority_protocol`](https://github.com/baselabs/bounded_authority_protocol)
  — the protocol monorepo: the wire specs this package signs (`spec/bap-v1.md`,
  `spec/bap-local-loopback-http-v1.md`, `spec/bap-v2.md`, `spec/bap-v3.md`) and the governing
  ADRs.
- [`baselabs/bounded_authority_report_adapter`](https://github.com/baselabs/bounded_authority_report_adapter)
  — the Elixir reference implementation this package ports; signing behavior tracks it, and
  divergences carry a recorded decision.

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

## The four v2 signers

| Function | Object | Role |
|---|---|---|
| `signV2Report` | holder proof (the v2 grant passes through untouched) | holder |
| `signV2Anchor` | boundary anchor | role-agnostic |
| `signV2KeyTransition` | key transition | role-agnostic |
| `signV2Grant` | grant | issuer-only, structurally gated |

Before 0.5.0 contract-major 2 had no signing surface in this package. The v2 functions take
the same Ed25519 `KeyHandle` as the v1 functions and compose through the verifier package's
public v2 signing inputs (`v2.grantSigningInput`, `v2.proofSigningInput`,
`v2.boundaryAnchorSigningInput`, `v2.keyTransitionSigningInput`) and `v2.assembleCompact`, so
the bytes are the verifier's v2 format and nothing more: `v: 2` payloads, the `BAP2-*` domain
separators, and the five-kind selector algebra (`all`, `equals`, `one_of`, `lte`, `gte`; a
range bound is integer- or float-tagged). The same gates apply: the C1 role gate, the
wrong-key guard, the atomic identity snapshot, and the weak-key refusal. The local-loopback
profile is contract-major-1-bound and has no v2 form. Each major verifies only its own bytes:
`checkEnvelope` refuses a v2 envelope and `v2.checkEnvelope` refuses a v1 one.

```ts
const grant = await signV2Grant({
  issuer: "https://issuer.example.test", grantId: "urn:example:grant:2",
  audiences: ["https://resource.example.test"],
  issuedAt: 1_731_728_000, notBefore: 1_731_728_000, expiresAt: 1_731_736_000,
  holderThumbprint: holderThumbprintB64,
  operations: [{ name: "transfer", selectors: [{ kind: "lte", path: ["amount"], value: { t: "int", v: 10_000 } }] }],
}, issuerHsmHandle);
// then signV2Report(...) with the holder's handle, and v2.checkEnvelope(...) on the receiving side
```

## The four v3 signers (ES256)

| Function | Object | Role |
|---|---|---|
| `signV3Report` | holder proof (the v3 grant passes through untouched) | holder |
| `signV3Anchor` | boundary anchor | role-agnostic |
| `signV3KeyTransition` | key transition | role-agnostic |
| `signV3Grant` | grant | issuer-only, structurally gated |

The v3 surface mirrors the v1 functions under the `BAP3-ES256-SHA256` suite: `alg: "ES256"`
protected headers, payload `v: 3`, the `BAP3-REQUEST\0` digest prefix, the EC proof JWK
`{"crv":"P-256","kty":"EC","x":…,"y":…}` with the RFC 7638 EC thumbprint as `cnf.jkt`, the
five-kind selector algebra (including `lte`/`gte`), 65-byte uncompressed-SEC1 raw public
keys (`0x04 || x || y`), and 64-byte raw `r || s` signatures with **low-S normalization** —
`s` is replaced by `n − s` when high, so every emitted signature satisfies
`0 < s ≤ (n−1)/2` and cannot be re-spelled into a second valid encoding (ECDSA malleability;
the backend emits high-`s` about half the time). The v3 key-handle contract
(`Es256KeyHandle`) keeps the same custody boundary with the suite's widths. The
local-loopback profile is contract-major-1-bound and has no v3 form. The v3 producing profile
is authored in this package (delegating composition to the verifier's v3 producers remains a
recorded, owner-gated switch), and the compacts CI produces under it cross-verify through
the verifier package's own v3 surface — no self-round-trip claims.

## Quickstart — an edge agent proves a request

```ts
import { signGrant, signReport } from "@bounded-authority-protocol/signer";

// Issuer side: an issuer-role handle signs the capability grant.
const grantResult = await signGrant(
  {
    issuer: "https://issuer.example.test",
    grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"],
    issuedAt: 1_731_728_000, notBefore: 1_731_728_000, expiresAt: 1_731_736_000,
    holderThumbprint: holderThumbprintB64, // RFC 7638 thumbprint of the holder key
    operations: [{ name: "transfer", selectors: [{ kind: "all" }] }],
  },
  issuerHsmHandle, // { signingIdentity(): { role: "issuer", keyId, publicKey }, sign, ... }
);
if (!grantResult.ok) throw new Error(`grant signing failed: ${grantResult.error}`);

// Holder side: the agent's handle signs the proof binding THIS request.
const proofResult = await signReport(
  {
    grantCompact: grantResult.value.grant, operation: "transfer", method: "POST",
    targetUri: "https://resource.example.test/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000",
    castArguments: { t: "object", v: new Map([["amount", { t: "int", v: 5000 }]]) },
  },
  holderHandle,
  { proofId: "urn:example:proof:1", issuedAt: 1_731_728_030 },
);
if (!proofResult.ok) throw new Error(`proof signing failed: ${proofResult.error}`);
const envelope = proofResult.value; // { grant, proof }

// The receiver verifies with the verifier package, never trusting this library:
// checkEnvelope(envelope.grant, envelope.proof, expected) returns cryptographic facts.
```

Every signer returns a result to check before use: `{ ok: true, value }` or
`{ ok: false, error }`. The verifier README's
[Pairing with the signer](https://github.com/baselabs/bounded_authority_protocol_typescript#pairing-with-the-signer)
section runs this flow through `checkEnvelope` with every expected input spelled out.

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

The v3 suite takes the same contract shape under `Es256KeyHandle` with the suite's fixed
widths: `sign()` returns the 64-byte raw `r || s` (a high-`s` from the custodian is fine —
the library normalizes before emission), `publicKey()` the 65-byte uncompressed-SEC1 point,
and `thumbprint()` the RFC 7638 EC thumbprint.

Two load-bearing rules port unchanged from the Elixir adapter (both v1 and v3):

- **The C1 gate** — `signGrant` resolves the handle's role, key id, and public key as ONE
  atomic `signingIdentity()` snapshot and fails closed before `sign()` is ever called unless
  the role is `issuer`. A holder handle can never mint its own capability.
- **The wrong-key guard** — the shared signing tail verifies every signature against the
  resolved public key *before* assembly, with the verifier package's strict functions
  (`verifyStrict` for Ed25519, `es256VerifyStrict` for ES256, which also refuses a high-`s`
  signature, so a missed low-S normalization fails closed). A handle whose `sign()` used a
  different key (a rotation race, a misconfigured signing service) fails loudly as
  `signing_failed`, never a silent false-success deferred to the verifier. A handle that
  returns `r` or `s` outside `(0, n)` is `signing_failed` too. The handle gets its own copy of
  the message (it may rewrite or transfer it), and the library keeps private copies of the
  message, the resolved key and the returned signature, so nothing the handle still holds can
  change what is checked or assembled. A handle method or getter that throws, a `null`
  snapshot or a Proxy-wrapped key is `invalid_key_handle`; a throwing `onEvent` listener is
  ignored.

The local-loopback profile is selected by function name — never inferred: the nonce is
required, and the target must be exactly `http://127.0.0.1[:port]/…` or `http://[::1][:port]/…`
(`localhost` and every non-canonical spelling fail closed).

## WebCrypto key handles

Since 0.6.0, two factories build the handles above from a WebCrypto key pair whose private key
is **non-extractable**, so a page (or Deno, Bun or Node) signs with a key it cannot export:

```ts
import { ed25519KeyHandle, es256KeyHandle, signReport, signV3Report } from "@bounded-authority-protocol/signer";

// You create the pair and own its lifetime; the library never generates, imports or exports a private key.
const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
const made = await ed25519KeyHandle(pair, { keyId: "agent-key-1" }); // role: "holder" (default) or "issuer"
if (!made.ok) throw new Error(made.error); // "invalid_key_handle"; the factory never throws or rejects
const envelope = await signReport(report, made.value, { proofId });

// Contract-major 3 (ES256):
const ecPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const ec = await es256KeyHandle(ecPair);
```

The parameter type is structural: a DOM `CryptoKeyPair` and Node's `webcrypto.CryptoKeyPair` pass
without a cast. One exception, from the Node types: `@types/node` (26.6.5) types
`webcrypto.subtle.generateKey({ name: "Ed25519" }, ...)` as `Promise<CryptoKey>`, so cast its
result:

```ts
import { webcrypto } from "node:crypto";
const pair = (await webcrypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as unknown as webcrypto.CryptoKeyPair;
```

**What the factory checks**, in this order. Any failure is `invalid_key_handle`, with no detail:

1. a secure context with `crypto.subtle` (on a plain-HTTP page there is none, and nothing you
   passed is read);
2. the options (`keyId` a non-empty string, `role` `"holder"` or `"issuer"`), read from the
   options object's own data properties only: an inherited `role` or `keyId`, including one on a
   polluted `Object.prototype`, is ignored. The pair's two keys are read the same way;
3. both keys are real `CryptoKey`s: each must be structured-cloneable (a `Proxy` never is), and
   every fact is read through the `CryptoKey.prototype` getters, never through `key.extractable`,
   so a shadowed property, a plain object or a `Proxy` is refused;
4. a private and a public key;
5. the private key is non-extractable (always; there is no option to allow an extractable key);
6. `Ed25519` for both keys, or `ECDSA` on `P-256` for both;
7. the public key's raw export: 32 bytes, canonical, not small-order and torsion-free; or the
   65-byte uncompressed point on the curve;
8. one probe signature with the private key over a fixed message containing a zero byte (so it
   is never a JWS signing input), verified strictly against that export. A mismatched pair, or a
   relabeled algorithm (an X25519 pair renamed Ed25519), fails here.

Everything the factory and the handle take from the environment is captured when the module loads:
`crypto.subtle`, `SubtleCrypto.prototype.sign` and `exportKey`, the `CryptoKey` getters,
`structuredClone` and `Reflect.apply`. A script that patches them later changes neither the checks
nor what an existing handle calls.

**The handle signs only JWS signing inputs.** Its `sign()` accepts only bytes shaped
`base64url "." base64url` and rejects anything else; within the signers that is `signing_failed`.
The message must be a `Uint8Array` from the same realm as the library: a typed array made in another
iframe or `vm` context fails the `instanceof Uint8Array` test and is rejected. The signers always pass
their own copy, so this matters only if you call `handle.sign()` yourself.
The ES256 handle returns WebCrypto's raw `r || s` unchanged (high-`s` about half the time), and the
shared v3 tail normalizes it to low-`s` and verifies it strictly, exactly as for your own handles.
The handle is frozen, its only properties are its methods, and the `CryptoKey` lives only in its
closure; `JSON.stringify(handle)` is `{}`.

**Threat model.** Read this before you keep a signing key in a page.

- **Non-extractable stops export, not use.** Any script running in the origin that reaches the
  handle or the `CryptoKey` (or reads the key back from IndexedDB) can sign silently, with no
  prompt: an XSS payload, a compromised dependency, an extension with page access. A signature
  from these handles proves that code in that origin used the key, not that a person approved
  the bytes. Approval (a user gesture, a confirmation screen, rate limits) is yours to add.
  Containment belongs to the protocol and the host runtime: narrow grants, short `exp`, exact
  operations and audiences, and the runtime's replay and revocation.
- **One key per purpose.** The handle signs any JWS signing input, so a pair used here must not
  sign anything else (another protocol, another JWS consumer).
- **Non-extractable is a browser property only.** On Node and Bun, any code in the process can
  export a non-extractable private key with `KeyObject.from(key).export()` (Node 24 prints a
  deprecation warning and still exports). Deno refuses. On a server, prefer a handle that reaches
  a KMS or HSM.
- **The extractable refusal is a guard against accidents, not against the key's holder.** It
  stops an exportable key from being paired with a handle meant for a non-exportable one. The
  getter reads and the structured-clone check refuse every disguise tested (a shadowed property, a
  plain object, a `Proxy`, including one that lies to Deno's getters), but whoever owns the key
  already controls it (on Node and Bun they can export it anyway), so the refusal is never a
  security boundary against that caller.
- **Persistence is yours.** The library stores nothing. A `CryptoKey` you save to IndexedDB stays
  non-extractable, and lives in the browser profile on disk; clearing site data, eviction and
  private browsing lose it. Rotating the pair means building a new handle (the public key is a
  snapshot).
- **Not hardware-backed.** WebCrypto keys are browser-managed software keys with no attestation.
- **Other realms.** A key generated in a same-origin iframe, or generated in a dedicated worker
  and posted to the page, is accepted (the getters brand-check; there is no `instanceof` test); the
  browser lanes test both. Deno cannot hand a `CryptoKey` across realms: its structured clone of a
  `CryptoKey` is not a usable key, so generate keys where you sign.
- **Harden the page that holds a key:** the strict CSP above, Trusted Types, Subresource
  Integrity, a minimal dependency set, and a dedicated origin for key use. In-page verification
  stays display-only.

Ed25519 in WebCrypto needs Chrome 137, Firefox 129 or Safari 17 or later; ECDSA P-256 is
everywhere. CI exercises the factories in Chromium, Firefox and WebKit on Linux, Node, Deno and
Bun. Linux WebKit is evidence for that WebKit build only, not for Safari's WebCrypto.

## Browsers, Deno, Bun and workers

The package is ESM-only, has no side effects on import (`"sideEffects": false`), and uses no
Node API: no `node:*` module, no `Buffer`, no `process`. Every cryptographic operation it
performs itself (the post-sign verify, SHA-256) comes from the verifier package, which picks
its own backend through its `"imports"` conditions, so a browser bundle, Deno and Bun get the
verifier's pure-JavaScript portable backend and Node.js keeps `node:crypto`:

| Runtime | Verifier `BACKEND_ID` |
|---|---|
| Node.js (default conditions) | `"node"` |
| Node.js with `--conditions=bap-portable` | `"portable"` |
| Deno, Bun | `"portable"` |
| Browsers and bundlers targeting them, workers | `"portable"` |

```ts
import { BACKEND_ID } from "@bounded-authority-protocol/verifier";
// "node" or "portable": which verifier backend this build resolved. Signing behaves the same in both.
```

The signer never touches private-key bytes: signing is always a handle's `sign()`, wherever and
however that handle is implemented. The only WebCrypto it uses is in the
[WebCrypto key handles](#webcrypto-key-handles): `crypto.subtle.sign` with your non-extractable
`CryptoKey`, and `exportKey("raw")` of the public key.

**In-page verification is display-only, never a trust decision.** If a page signs and then
verifies an envelope (as the playground does), that result is for showing to a person. It
must not authorize anything, feed a trust decision, or be sent anywhere as evidence of
authority: the page's own scripts, browser extensions and injected code share its origin and
can change both the inputs and the answer. The trusted decision stays with the host runtime
that holds the trusted keys.

The package works under a strict Content Security Policy (`default-src 'none'; script-src
'self'; connect-src 'self'`, no `'unsafe-eval'`): it uses no `eval`, no `Function` constructor
and no dynamic `import()`. The default `proofId` comes from `crypto.randomUUID()`, which
browsers provide only in a secure context (HTTPS or `localhost`). On a plain-HTTP page, pass
`proofId` explicitly; without it the report signers return the closed `producer_error`.

Bundle size (esbuild, minified, browser target, tree-shaken from the package entry, verifier
included): every export 184 KB (49 KB gzip); `{ signReport }` 113 KB (31 KB gzip);
`{ signV2Report }` 111 KB (30 KB gzip); `{ signV3Report }` 69 KB (25 KB gzip). CI fails a
change that grows any of these by more than 10%.

## Evidence

Every compact this library produces is verified in CI through the independent verifier
package (`checkEnvelope`, `verifyGrant`, `verifyHistoricalAnchor`, `verifyKeyTransition`, the
loopback profile's `checkEnvelope`, and the `v2` and `v3` namespaces' equivalents) — no
self-round-trip claims. The v1 and v2 profiles compose through the verifier package's own
producers; the v3 producing profile is authored here (delegating composition to the verifier's
v3 producers remains a recorded, owner-gated switch), and its compacts cross-verify through
the verifier package's `v3` surface — the flip the former gap pin anticipated — while every
produced signature is additionally pinned at the byte level: verified over the exact RFC 7515
signing input under node:crypto, both in the raw `ieee-p1363` form and re-encoded as DER.
The closure gates (C1 role gate, wrong-key guard, loopback
nonce and canonical-target admission, atomic-identity requirement, and the v3 additions:
low-S normalization and the P-256 on-curve check) are red-capable: mechanically removing
the check fails its test. CI runs the full gate on `ubuntu-24.04` only: CI is
Linux only. The clone → build → test contract holding on macOS and Linux
is a developer-setup property, proven on a developer machine, not a CI matter. Windows
developers use WSL2 (clone inside the WSL filesystem, not under `/mnt/c`), which is the
Linux path; no native-Windows developer path is maintained.

The sign-then-verify battery (v1, loopback, v2 and v3 envelopes, grants, anchors and key
transitions; a wrong-key handle on every major; 64 ES256 reports from a handle that emits
high-`s` about half the time, each normalized and verified) runs on Node 22.23.1 and 24.19.0
with each verifier backend, on Deno 2.5.6 and Bun 1.3.14, and in Chromium, Firefox and WebKit
(Linux CI, Playwright, under the strict CSP above); every lane first asserts the verifier
`BACKEND_ID` it expects. A lane on a non-secure origin, in each browser, checks the closed
`producer_error` for a missing default `proofId` and that both key-handle factories refuse without
touching their arguments. The WebCrypto key-handle battery (104 checks, 109 in browsers, with each engine's
own keys: accept, sign then verify on v1, v2 and v3 over 64 distinct inputs, the extractable,
type, algorithm, weak-key, mismatched-pair and relabeled-algorithm refusals, roles, no key
exposure, the JWS-shape restriction, inherited and polluted options, `SubtleCrypto` methods patched
after load, every signer with factory handles, and an iframe key and a worker-posted key in the
browsers) runs in every one of those lanes and records an engine capability row. Guards keep Node APIs out of `src/`: a
browser typecheck with no ambient types, lint rules (Node modules and globals, dynamic code,
`@noble` and WebCrypto), a scan of the browser bundle for unresolved globals, and a
packed-tarball consumer typecheck with `skipLibCheck: false`. Linux WebKit is evidence for
this pure-JavaScript code only, not for Safari. The publish lane is separate: it re-verifies
(build, typecheck, lint, guards, tests, the runtime, tarball and browser lanes, and
`npm audit signatures`) on Node 24 — the npm >= 11.5 that trusted publishing requires —
before staging a release that a human approves.

## Versioning and compatibility

Package versions follow SemVer. Before 1.0 the minor position is the breaking boundary, so
npm caret ranges such as `^0.2.1` never select `0.3.0`.

0.6.x adds the WebCrypto key handles (`ed25519KeyHandle`, `es256KeyHandle`) and refuses a
caller's off-curve P-256 key at resolution (`invalid_key_handle`, before `sign()`); it keeps the
verifier `^0.7.0`. 0.5.x depends on `@bounded-authority-protocol/verifier` `^0.7.0`, runs in
browsers, Deno and Bun, adds the contract-major-2 signers, and checks every ES256 signature with the verifier's
strict `es256VerifyStrict` after low-S normalization. Its `"exports"` map keeps deep imports
such as `@bounded-authority-protocol/signer/dist/src/v3.js` resolving through a `"./*"`
passthrough, but deep imports are unsupported API and may be closed in a future 0.x minor;
import from the package root. 0.4.x depends on `@bounded-authority-protocol/verifier`
`^0.6.0` and refuses small-order and non-canonical Ed25519 key handles. 0.3.x depends on `@bounded-authority-protocol/verifier`
`^0.5.0` and signs through its producers, so it inherits that release's stricter identifier
admission. Identifiers with repeated fragment delimiters, raw brackets in userinfo or outside
authority, or malformed bracketed IPv6 hosts such as `http://[abc]/x` now return
`producer_error` instead of producing bytes a verifier would reject. Valid identifiers, including bracketed IPv6
literals such as `http://[::1]/`, sign as before. Compatibility with other implementations
is governed by the wire contract-majors (this package signs majors 1, 2 and 3), not by package
version numbers. Release notes are in [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
