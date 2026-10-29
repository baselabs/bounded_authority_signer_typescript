# @bounded-authority-protocol/signer

[![npm](https://img.shields.io/npm/v/@bounded-authority-protocol/signer)](https://www.npmjs.com/package/@bounded-authority-protocol/signer)
[![CI](https://github.com/baselabs/bounded_authority_signer_typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/baselabs/bounded_authority_signer_typescript/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

The signing side of the Bounded Authority Protocol, in TypeScript. An issuer uses it to sign a
**grant**: the holder of one key may invoke named operations, with constraints on their arguments,
at named resources, within a time window. The holder (an agent, an app, a service) uses it to sign a **proof** that binds
one request to that grant. A resource server checks the pair with
[`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
and gets facts back. The same package signs boundary anchors and key transitions for audit chains.

You pass a **key handle**: an object whose `sign()` reaches your own key custody (a KMS, an HSM, a
WebCrypto key, or an in-process key in tests). The private key never enters the library, and every
handle method may be async.

**Try it in your browser first:** the [envelope playground](https://baselabs.github.io/bounded_authority_signer_typescript/)
runs this package and the verifier in the page, with keys your browser generates.

What it is not: it does not verify (that is the verifier package), decide whether a request is
allowed, store keys, transport anything, or track replay and revocation (that is your authority
runtime).

Contents: [Install](#install) · [Quickstart](#quickstart) ·
[The key-handle contract](#the-key-handle-contract) · [API reference](#api-reference) ·
[Errors](#errors) · [Contract-major 2](#contract-major-2-ed25519-with-range-selectors) ·
[Contract-major 3](#contract-major-3-es256) ·
[Anchors and key rotation](#anchor-a-chain-and-rotate-its-key) ·
[Loopback](#sign-for-a-local-app-loopback) · [Testing](#test-your-integration) ·
[WebCrypto key handles](#webcrypto-key-handles) ·
[Browsers, Deno, Bun](#browsers-deno-bun-and-workers) · [How it is tested](#how-this-package-is-tested) ·
[Versioning](#versioning-and-compatibility) · [Protocol family](#protocol-family) ·
[Development](#development)

It signs three wire contract-majors, each with its own functions:

| Contract-major | Suite | Signers |
|---|---|---|
| 1 | Ed25519 | `signGrant`, `signReport`, `signLocalLoopbackReport`, `signAnchor`, `signKeyTransition` |
| 2 | Ed25519, adds the `lte`/`gte` range selectors | `signV2Grant`, `signV2Report`, `signV2Anchor`, `signV2KeyTransition` |
| 3 | ES256 (ECDSA P-256, SHA-256) | `signV3Grant`, `signV3Report`, `signV3Anchor`, `signV3KeyTransition` |

## Install

```bash
npm install @bounded-authority-protocol/signer@0.6.0 @bounded-authority-protocol/verifier@1.0.0
```

That is the latest release on npm. This README documents the source on `main`, version 0.6.0,
which is not released yet; the parts only 0.6.0 has are marked **0.6.0**.

The signer's one runtime dependency is the verifier. Install the verifier yourself too when your
code imports it, as every example here does (pnpm, for one, does not let you import a package you
did not install). It runs on Node.js 22 or later, current browsers, Deno and Bun.

## Quickstart

An issuer grants an agent read access to one repository; the agent proves one request; the
resource server verifies it. You need Node.js 22 or later. In an empty directory, create an ES
module project (the examples use top-level `await`), install both packages, and install
[tsx](https://www.npmjs.com/package/tsx) to run TypeScript:

<!-- readme-sample: setup -->
```bash
npm init -y && npm pkg set type=module
npm install @bounded-authority-protocol/signer@0.6.0 @bounded-authority-protocol/verifier@1.0.0
npm install --save-dev tsx
```

First, a key handle over in-process keys, for trying the library (in production, `sign()` calls
your KMS, HSM or WebCrypto key instead). Save it as `key-handle.ts`:

<!-- readme-sample: file key-handle.ts -->
```ts
import { generateKeyPairSync, sign } from "node:crypto";
import { jwkFromPublicKey, thumbprint, v3 } from "@bounded-authority-protocol/verifier";
import type { Es256KeyHandle, KeyHandle, KeyRole } from "@bounded-authority-protocol/signer";

const fromBase64url = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "base64url"));

/** An Ed25519 handle over a fresh in-process key (contract-majors 1 and 2). */
export function testKeyHandle(keyId: string, role: KeyRole = "holder"): KeyHandle {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = fromBase64url(publicKey.export({ format: "jwk" }).x!);
  return {
    sign: (message) => new Uint8Array(sign(null, message, privateKey)),
    publicKey: () => raw,
    thumbprint: () => thumbprint(jwkFromPublicKey(raw)),
    keyIdentity: () => ({ keyId, publicKey: raw }),
    signingIdentity: () => ({ role, keyId, publicKey: raw }),
  };
}

/** An ES256 handle over a fresh in-process P-256 key (contract-major 3). */
export function testEs256KeyHandle(keyId: string, role: KeyRole = "holder"): Es256KeyHandle {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const raw = new Uint8Array([0x04, ...fromBase64url(x), ...fromBase64url(y)]);
  return {
    sign: (message) => new Uint8Array(sign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" })),
    publicKey: () => raw,
    thumbprint: () => v3.thumbprint({ crv: "P-256", kty: "EC", x, y }),
    keyIdentity: () => ({ keyId, publicKey: raw }),
    signingIdentity: () => ({ role, keyId, publicKey: raw }),
  };
}
```

Then `quickstart.ts`, and run it with `npx tsx quickstart.ts`:

<!-- readme-sample: run -->
```ts
import { signGrant, signReport } from "@bounded-authority-protocol/signer";
import { checkEnvelope, strUtf8, type Tagged } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const issuer = testKeyHandle("issuer-key-1", "issuer"); // the authorization server's key
const agent = testKeyHandle("agent-key-1");             // the holder: the agent's own key

// 1. The issuer grants the agent one operation on one repository, for two hours.
const grant = await signGrant({
  issuer: "https://issuer.example",
  grantId: "urn:example:grant:1",
  audiences: ["https://code.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_232_800,
  holderThumbprint: await agent.thumbprint(),
  operations: [{
    name: "read_file",
    selectors: [{ kind: "equals", path: ["repository"], value: { t: "string", v: strUtf8("example/website") } }],
  }],
}, issuer);
if (!grant.ok) throw new Error(`signGrant: ${grant.error}`);

// 2. The agent proves one request under that grant.
const args: Tagged = { t: "object", v: new Map<string, Tagged>([
  ["repository", { t: "string", v: strUtf8("example/website") }],
  ["path", { t: "string", v: strUtf8("README.md") }],
]) };
const request = {
  method: "GET",
  targetUri: "https://code.example/files",
  invocationId: "0f8d5a5e-7c3b-4e7a-9a51-2f4c1d6b8e90", // a lowercase RFC 4122 UUID
  operation: "read_file",
  castArguments: args,
};
const envelope = await signReport({ grantCompact: grant.value.grant, ...request }, agent, { issuedAt: 1_767_225_660 });
if (!envelope.ok) throw new Error(`signReport: ${envelope.error}`);

// 3. The resource server verifies the pair with the verifier package and gets facts, not a decision.
const facts = checkEnvelope(envelope.value.grant, envelope.value.proof, {
  ...request,                       // the request the server actually received
  trustedIssuer: { keyId: "issuer-key-1", publicKey: await issuer.publicKey() }, // a key the server already trusts
  issuer: "https://issuer.example", // the issuer the grant must name
  audience: "https://code.example", // this server: one of the grant's audiences
  evaluationTime: 1_767_225_700,    // "now", in Unix seconds: the verifier reads no clock
  clockSkew: 60,                    // seconds of tolerance between the parties' clocks
  proofMaxAge: 300,                 // seconds a proof stays acceptable after its issuedAt
  nonce: { kind: "not_required" },  // this server issues no nonces
});
if (!facts.ok) throw new Error("the envelope did not verify");
console.log(`verified: ${facts.value.operation} under ${facts.value.grantId}`);
```

Output:

<!-- readme-output -->
```text
verified: read_file under urn:example:grant:1
```

Every signer returns `{ ok: true, value }` or `{ ok: false, error }`; check `ok` before reading
`value`. Change the `repository` argument to another value and `checkEnvelope` returns
`{ ok: false }`: the proof still signs, but the grant's `equals` selector does not match.

## The key-handle contract

A handle is any object with these methods (the exported declarations, verbatim; the comments are added):

<!-- readme-sample: types -->
```ts
type KeyRole = "issuer" | "holder";

interface AtomicKeyIdentity {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}

interface AtomicSigningIdentity extends AtomicKeyIdentity {
  readonly role: KeyRole;
}

// Contract-majors 1 and 2, and the local-loopback profile (Ed25519).
interface KeyHandle {
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;                     // 64-byte signature
  publicKey(): Uint8Array | Promise<Uint8Array>;                                    // 32 bytes
  thumbprint(): string | Promise<string>;                                           // RFC 7638, base64url
  keyIdentity?(): AtomicKeyIdentity | Promise<AtomicKeyIdentity>;                   // anchors, key transitions
  signingIdentity?(): AtomicSigningIdentity | Promise<AtomicSigningIdentity>;       // grants
}

// Contract-major 3 (ES256).
interface Es256KeyHandle {
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;                     // 64-byte raw r || s
  publicKey(): Uint8Array | Promise<Uint8Array>;                                    // 65 bytes: 0x04 || x || y
  thumbprint(): string | Promise<string>;                                           // RFC 7638 EC, base64url
  keyIdentity?(): { keyId: string; publicKey: Uint8Array } | Promise<{ keyId: string; publicKey: Uint8Array }>;
  signingIdentity?(): Promise<AtomicSigningIdentity> | AtomicSigningIdentity;
}
```

What the library does with a handle:

- **Which methods it calls.** Every signer calls `sign()`. Report signers read `publicKey()`;
  anchor and key-transition signers read `keyIdentity()`; grant signers read `signingIdentity()`.
  `thumbprint()` is for you: put the holder's thumbprint in the grant's `holderThumbprint`.
- **The issuer-role gate.** A grant signer reads `signingIdentity()` once and fails closed with
  `invalid_key_handle`, before `sign()` is ever called, unless the snapshot's own `role` is
  `"issuer"`. A holder handle can never mint its own grant. `role`, `keyId` and `publicKey` count
  only as the snapshot's own data properties, never inherited ones or getters (**0.6.0**; 0.5.0 also
  read inherited ones).
- **Key checks before signing.** An Ed25519 key must be 32 bytes, canonical and not small-order; a
  P-256 key must be the 65-byte uncompressed point on the curve (checked here from **0.6.0**; 0.5.0
  refused an off-curve key later, as `producer_error`). Anything else is `invalid_key_handle`, and
  `sign()` is not called.
- **The wrong-key guard.** Every signature is verified against the resolved public key before
  assembly, with the verifier's strict checks (`verifyStrict` for Ed25519; for ES256 the library
  first normalizes `s` to low-S, then `es256VerifyStrict` checks it). A handle whose `sign()` used a
  different key (a rotation race, a misconfigured signing service) gets `signing_failed`, never a
  compact that only the verifier would reject.
- **Copies.** `sign()` receives its own copy of the message, and the library keeps private copies of
  the message, the key and the signature, so nothing the handle still holds can change what is
  checked or assembled.
- **Faults.** A handle method or getter that throws, a `null` snapshot or a Proxy-wrapped key is
  `invalid_key_handle`; a `sign()` that throws or returns anything but a 64-byte `Uint8Array` is
  `signing_failed`. An `onEvent` listener that throws is ignored.

An ES256 custodian may return a high `s`: the library replaces it with `n − s`, so every emitted
signature has `0 < s ≤ (n−1)/2` and cannot be re-spelled into a second valid encoding. An `r` or
`s` outside `(0, n)` is `signing_failed`.

## API reference

### Signers

Every signer is `async (input, handle, opts?) => SignerResult<value>`.

| Function | Input | Handle | Needs | `value` |
|---|---|---|---|---|
| `signGrant` | `GrantInput` | `KeyHandle` | `signingIdentity()`, role `"issuer"` | `{ grant }` |
| `signReport` | `ReportInput` | `KeyHandle` | `publicKey()` | `{ grant, proof }` |
| `signLocalLoopbackReport` | `ReportInput` (nonce required) | `KeyHandle` | `publicKey()` | `{ grant, proof }` |
| `signAnchor` | `AnchorInput` | `KeyHandle` | `keyIdentity()` | `{ anchor }` |
| `signKeyTransition` | `TransitionInput` | `KeyHandle` | `keyIdentity()` | `{ keyTransition }` |
| `signV2Grant` | `V2GrantInput` | `KeyHandle` | `signingIdentity()`, role `"issuer"` | `{ grant }` |
| `signV2Report` | `V2ReportInput` | `KeyHandle` | `publicKey()` | `{ grant, proof }` |
| `signV2Anchor` | `V2AnchorInput` | `KeyHandle` | `keyIdentity()` | `{ anchor }` |
| `signV2KeyTransition` | `V2TransitionInput` | `KeyHandle` | `keyIdentity()` | `{ keyTransition }` |
| `signV3Grant` | `V3GrantInput` | `Es256KeyHandle` | `signingIdentity()`, role `"issuer"` | `{ grant }` |
| `signV3Report` | `V3ReportInput` | `Es256KeyHandle` | `publicKey()` | `{ grant, proof }` |
| `signV3Anchor` | `V3AnchorInput` | `Es256KeyHandle` | `keyIdentity()` | `{ anchor }` |
| `signV3KeyTransition` | `V3TransitionInput` | `Es256KeyHandle` | `keyIdentity()` | `{ keyTransition }` |

Every value field is a compact JWS as ASCII bytes (`Uint8Array`). A report signer's `grant` is the
`grantCompact` you passed, unchanged.

The package also exports the key-handle factories `ed25519KeyHandle` and `es256KeyHandle`
(**0.6.0**, see [WebCrypto key handles](#webcrypto-key-handles)), and these types: `KeyHandle`,
`Es256KeyHandle`, `KeyRole`, `AtomicKeyIdentity`, `AtomicSigningIdentity`, `SignerErrorCode`,
`SignerResult`, the input and option types named in this section, `SignerEvent`, `V2SignerEvent`,
`V3SignerEvent`, `V2OperationInput`, `V2SelectorInput`, from **0.6.0** `V3OperationInput` and
`V3SelectorInput` (see [Inputs](#inputs)), the value types `Envelope`, `GrantCompact`,
`AnchorCompact` and `TransitionCompact`, and (**0.6.0**) `WebCryptoKeyLike`, `WebCryptoKeyPairLike` and
`WebCryptoHandleOptions`.

### Inputs

`GrantInput` (and `V2GrantInput`, `V3GrantInput`):

| Field | Type | Rules |
|---|---|---|
| `issuer` | `string` | the issuer identifier, for example `https://issuer.example` |
| `grantId` | `string` | non-empty |
| `audiences` | `string[]` | the resources the grant is for; at least one |
| `issuedAt`, `notBefore`, `expiresAt` | `number` | Unix seconds, integers; `expiresAt` after `notBefore` |
| `holderThumbprint` | `string` | the holder key's RFC 7638 thumbprint, base64url (the holder handle's `thumbprint()`) |
| `operations` | `{ name, selectors }[]` | at least one; selector kinds `all`, `equals`, `one_of` on v1, plus `lte` and `gte` on v2 and v3 |

A selector is `{ kind: "all" }` (or the string `"all"`), `{ kind: "equals", path, value }`,
`{ kind: "one_of", path, values }`, or on v2 and v3 `{ kind: "lte" | "gte", path, value }` with an
`int`- or `float`-tagged bound. `path` names a member of the request's `castArguments`; every
selector of an operation must match. The signer does not evaluate selectors; the verifier does.

The operation and selector types: on v1 the verifier package's `OperationInput` and `SelectorInput`
(import them from `@bounded-authority-protocol/verifier`); on v2 `V2OperationInput` and
`V2SelectorInput`; on v3 `V3OperationInput` and `V3SelectorInput`, exported from the package root
from **0.6.0** (0.5.0 reached them only through a deep import):

<!-- readme-sample: types -->
```ts
import type { Tagged } from "@bounded-authority-protocol/verifier";

type V3SelectorInput =
  | "all"
  | { readonly kind: "all" }
  | { readonly kind: "equals"; readonly path: readonly string[]; readonly value: Tagged }
  | { readonly kind: "one_of"; readonly path: readonly string[]; readonly values: readonly Tagged[] }
  | { readonly kind: "lte"; readonly path: readonly string[]; readonly value: Tagged }
  | { readonly kind: "gte"; readonly path: readonly string[]; readonly value: Tagged };

interface V3OperationInput {
  readonly name: string;
  readonly selectors: readonly V3SelectorInput[];
}

```

`V2SelectorInput` and `V2OperationInput` declare the same members.

`ReportInput` (and `V2ReportInput`, `V3ReportInput`):

| Field | Type | Rules |
|---|---|---|
| `grantCompact` | `Uint8Array` | the grant the proof is for |
| `operation` | `string` | an operation the grant names |
| `method` | `string` | the HTTP method, for example `"POST"` |
| `targetUri` | `string` | the absolute request URI; on the loopback profile `http://127.0.0.1[:port]/…` or `http://[::1][:port]/…` only |
| `invocationId` | `string` | a lowercase RFC 4122 UUID |
| `castArguments` | `Tagged` | the request's arguments as the verifier's type-tagged JSON: `{ t: "null" }`, `{ t: "bool", v: boolean }`, `{ t: "int" \| "float", v: number }`, `{ t: "string", v: Uint8Array }` (UTF-8 bytes: `strUtf8("…")` from the verifier), `{ t: "array", v: Tagged[] }`, `{ t: "object", v: Map<string, Tagged> }` |
| `nonce` | `string`, optional | required and non-empty for `signLocalLoopbackReport` |

`AnchorInput` (and v2, v3): `anchorId` and `chainId` (non-empty strings), `sequence` (a
non-negative integer), `chainHash` (32 bytes).

`TransitionInput` (and v2, v3): `transitionId`, `chainId` and `nextKeyId` (non-empty strings),
`effectiveAt` (Unix seconds, an integer), `nextPublicKey` (32 bytes; 65 bytes for v3).

### Options

`SignOpts` (and `V2SignOpts`, `V3SignOpts`), all optional:

| Option | Used by | Default |
|---|---|---|
| `issuedAt` | report signers: the proof's `iat`, Unix seconds | the wall clock |
| `proofId` | report signers: the proof's `jti` | `crypto.randomUUID()`; on a plain-HTTP page, where that is absent, the result is `producer_error`, so pass one |
| `anchoredAt` | anchor signers, Unix seconds | the wall clock |
| `bounds` | every signer: size limits for the verifier's producers | the verifier's defaults |
| `onEvent` | every signer: called with `{ kind, phase }`, `phase` `"start"` then `"stop"` or `"error"` | none |

The `kind` is `report`, `local_loopback_report`, `anchor`, `grant` or `key_transition` on v1, and
the same names prefixed `v2_` or `v3_` on the other majors (there is no loopback form there).

## Errors

The error codes are a closed set (`SignerErrorCode`). No error carries key material, nonce values or
report content.

| Code | Returned by | Meaning | Fix |
|---|---|---|---|
| `invalid_report` | report signers | a field is missing, empty or the wrong type, or the loopback `nonce` is missing | pass every `ReportInput` field |
| `invalid_grant` | grant signers | a field is missing or the wrong type (non-array `audiences` or `operations`, non-integer times, empty strings) | pass every `GrantInput` field |
| `invalid_anchor` | anchor signers | an empty id, a non-integer `sequence`, or a `chainHash` that is not 32 bytes | pass every `AnchorInput` field |
| `invalid_transition` | key-transition signers | an empty id, a non-integer `effectiveAt`, or a `nextPublicKey` of the wrong width | pass every `TransitionInput` field |
| `invalid_key_handle` | every signer, both factories | the handle is unusable: a method or getter threw; a key of the wrong width, or one the suite refuses (non-canonical or small-order Ed25519, a P-256 key off the curve); no `keyIdentity()` for an anchor or transition; no `signingIdentity()`, or a role other than `"issuer"`, for a grant; a factory check failed | fix the handle; a holder handle cannot sign grants |
| `signing_failed` | every signer | `sign()` threw, returned something other than a 64-byte `Uint8Array`, or returned a signature that does not verify against the handle's public key | make `sign()` use the key that `publicKey()` reports |
| `producer_error` | every signer | the protocol refused an input: a non-UUID `invocationId`, a malformed identifier or URI, no audiences or operations, `expiresAt` not after `notBefore`, a negative `sequence`, an exceeded bound, a loopback target other than `127.0.0.1` or `[::1]` over `http`; or no `proofId` could be generated | correct the value; pass `proofId` on a plain-HTTP page |

The type is closed, so a `switch` over it is checked for exhaustiveness. Here a holder handle
tries to sign a grant:

<!-- readme-sample: run -->
```ts
import { signGrant, type SignerErrorCode } from "@bounded-authority-protocol/signer";
import { testKeyHandle } from "./key-handle.js";

function advice(code: SignerErrorCode): string {
  switch (code) {
    case "invalid_report":
    case "invalid_grant":
    case "invalid_anchor":
    case "invalid_transition":
      return "a required input field is missing or has the wrong type";
    case "invalid_key_handle":
      return "the key handle cannot be used for this operation";
    case "signing_failed":
      return "the custodian's signature does not match the handle's public key";
    case "producer_error":
      return "the protocol refused an input value";
  }
}

const agent = testKeyHandle("agent-key-1"); // role "holder"
const result = await signGrant({
  issuer: "https://issuer.example", grantId: "urn:example:grant:self",
  audiences: ["https://code.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_232_800,
  holderThumbprint: await agent.thumbprint(),
  operations: [{ name: "read_file", selectors: [{ kind: "all" }] }],
}, agent);
if (!result.ok) console.log(`${result.error}: ${advice(result.error)}`);
```

<!-- readme-output -->
```text
invalid_key_handle: the key handle cannot be used for this operation
```

## Contract-major 2: Ed25519 with range selectors

The v2 signers take the same `KeyHandle` and emit the verifier's v2 format: `v: 2` payloads, the
`BAP2-*` domain separators, and the `lte` and `gte` selectors with an `int`- or `float`-tagged bound.
They compose through the verifier's own v2 signing inputs and `v2.assembleCompact`. Each major
verifies only its own bytes: `checkEnvelope` refuses a v2 envelope and `v2.checkEnvelope` refuses a
v1 one. Here a home assistant may set a thermostat between 18.5 and 24.5 °C:

<!-- readme-sample: run -->
```ts
import { signV2Grant, signV2Report } from "@bounded-authority-protocol/signer";
import { v2, type Tagged } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const home = testKeyHandle("home-issuer-1", "issuer");
const assistant = testKeyHandle("assistant-key-1");

const grant = await signV2Grant({
  issuer: "https://home.example", grantId: "urn:example:grant:thermostat",
  audiences: ["https://thermostat.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_312_000,
  holderThumbprint: await assistant.thumbprint(),
  operations: [{ name: "set_temperature", selectors: [
    { kind: "gte", path: ["celsius"], value: { t: "float", v: 18.5 } },
    { kind: "lte", path: ["celsius"], value: { t: "float", v: 24.5 } },
  ] }],
}, home);
if (!grant.ok) throw new Error(`signV2Grant: ${grant.error}`);
const grantCompact = grant.value.grant;

async function setTemperature(celsius: number): Promise<boolean> {
  const request = {
    method: "PUT", targetUri: "https://thermostat.example/setpoint",
    invocationId: "3b9e1c52-8d4f-4a1e-b7c2-5e6f7a8b9c0d", operation: "set_temperature",
    castArguments: { t: "object", v: new Map<string, Tagged>([["celsius", { t: "float", v: celsius }]]) } satisfies Tagged,
  };
  const envelope = await signV2Report({ grantCompact, ...request }, assistant, { issuedAt: 1_767_225_660 });
  if (!envelope.ok) throw new Error(`signV2Report: ${envelope.error}`);
  return v2.checkEnvelope(envelope.value.grant, envelope.value.proof, {
    ...request,
    trustedIssuer: { keyId: "home-issuer-1", publicKey: await home.publicKey() },
    issuer: "https://home.example", audience: "https://thermostat.example",
    evaluationTime: 1_767_225_700, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
  }).ok;
}

console.log(`21.5 °C verifies: ${await setTemperature(21.5)}`);
console.log(`30.5 °C verifies: ${await setTemperature(30.5)}`);
```

<!-- readme-output -->
```text
21.5 °C verifies: true
30.5 °C verifies: false
```

The local-loopback profile belongs to contract-major 1 and has no v2 form.

## Contract-major 3: ES256

The v3 signers sign the `BAP3-ES256-SHA256` suite: `alg: "ES256"` headers, payload `v: 3`, the
`BAP3-*` separators, the EC proof key `{"crv":"P-256","kty":"EC","x":…,"y":…}` with its RFC 7638
thumbprint as `cnf.jkt`, the five selector kinds, 65-byte uncompressed public keys and 64-byte raw
`r || s` signatures, low-S normalized (see [the key-handle contract](#the-key-handle-contract)). The
v3 signing inputs are built in this package; the v1 and v2 ones come from the verifier's producers.
Here a deploy bot may scale one service up to 10 replicas:

<!-- readme-sample: run -->
```ts
import { signV3Grant, signV3Report } from "@bounded-authority-protocol/signer";
import { strUtf8, v3, type Tagged } from "@bounded-authority-protocol/verifier";
import { testEs256KeyHandle } from "./key-handle.js";

const platform = testEs256KeyHandle("platform-issuer-1", "issuer");
const deployBot = testEs256KeyHandle("deploy-bot-1");

const grant = await signV3Grant({
  issuer: "https://platform.example", grantId: "urn:example:grant:scale-web",
  audiences: ["https://deploy.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_227_400,
  holderThumbprint: await deployBot.thumbprint(),
  operations: [{ name: "scale_service", selectors: [
    { kind: "equals", path: ["service"], value: { t: "string", v: strUtf8("web") } },
    { kind: "lte", path: ["replicas"], value: { t: "int", v: 10 } },
  ] }],
}, platform);
if (!grant.ok) throw new Error(`signV3Grant: ${grant.error}`);

const request = {
  method: "POST", targetUri: "https://deploy.example/scale",
  invocationId: "6a1f0d3c-2b4e-4f5a-8c6d-7e8f9a0b1c2d", operation: "scale_service",
  castArguments: { t: "object", v: new Map<string, Tagged>([
    ["service", { t: "string", v: strUtf8("web") }],
    ["replicas", { t: "int", v: 4 }],
  ]) } satisfies Tagged,
};
const envelope = await signV3Report({ grantCompact: grant.value.grant, ...request }, deployBot, { issuedAt: 1_767_225_660 });
if (!envelope.ok) throw new Error(`signV3Report: ${envelope.error}`);

const facts = v3.checkEnvelope(envelope.value.grant, envelope.value.proof, {
  ...request,
  trustedIssuer: { keyId: "platform-issuer-1", publicKey: await platform.publicKey() },
  issuer: "https://platform.example", audience: "https://deploy.example",
  evaluationTime: 1_767_225_700, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
});
console.log(`v3 envelope verifies: ${facts.ok}`);
```

<!-- readme-output -->
```text
v3 envelope verifies: true
```

`signV3Anchor` and `signV3KeyTransition` work like their v1 counterparts in the next section, with
an `Es256KeyHandle` and a 65-byte `nextPublicKey`:

<!-- readme-sample: run -->
```ts
import { signV3Anchor, signV3KeyTransition } from "@bounded-authority-protocol/signer";
import { base64urlDecode, strUtf8, v3 } from "@bounded-authority-protocol/verifier";
import { testEs256KeyHandle } from "./key-handle.js";

const current = testEs256KeyHandle("ledger-key-1");
const next = testEs256KeyHandle("ledger-key-2");
const fingerprint = async (handle: typeof current) => base64urlDecode(strUtf8(await handle.thumbprint()));
const chainHash = new Uint8Array(32); // the chain's hash at this sequence (all zero at genesis)

const anchor = await signV3Anchor(
  { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:ledger", sequence: 0, chainHash },
  current, { anchoredAt: 1_767_225_600 },
);
const transition = await signV3KeyTransition({
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:ledger",
  effectiveAt: 1_767_312_000, nextKeyId: "ledger-key-2", nextPublicKey: await next.publicKey(),
}, current);
if (!anchor.ok || !transition.ok) throw new Error("signing failed");

const currentKey = { keyId: "ledger-key-1", publicKey: await current.publicKey(), validFrom: 0, validBefore: null };
const nextKey = { keyId: "ledger-key-2", publicKey: await next.publicKey(), validFrom: 1_767_312_000, validBefore: null };
const anchorFacts = v3.verifyHistoricalAnchor(anchor.value.anchor, currentKey, {
  anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:ledger", keyId: "ledger-key-1",
  sequence: 0, anchoredAt: 1_767_225_600, chainHash, keyFingerprint: await fingerprint(current),
});
const transitionFacts = v3.verifyKeyTransition(transition.value.keyTransition, currentKey, nextKey, {
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:ledger", effectiveAt: 1_767_312_000,
  currentKeyId: "ledger-key-1", nextKeyId: "ledger-key-2",
  currentKeyFingerprint: await fingerprint(current), nextKeyFingerprint: await fingerprint(next),
});
console.log(`v3 anchor verifies: ${anchorFacts.ok}; v3 transition verifies: ${transitionFacts.ok}`);
```

<!-- readme-output -->
```text
v3 anchor verifies: true; v3 transition verifies: true
```

## Anchor a chain and rotate its key

A boundary anchor signs a checkpoint of a hash chain (an audit log, for example): its id, sequence
number and hash at that sequence. A key transition, signed by the current key, names the key that
takes over and when. Both need `keyIdentity()` and are role-agnostic. The verifier checks them
with `verifyHistoricalAnchor` and `verifyKeyTransition`:

<!-- readme-sample: run -->
```ts
import { signAnchor, signKeyTransition } from "@bounded-authority-protocol/signer";
import { publicKeyThumbprintRaw, verifyHistoricalAnchor, verifyKeyTransition } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const current = testKeyHandle("audit-key-1");
const next = testKeyHandle("audit-key-2");
const chainHash = new Uint8Array(32); // the chain's hash at this sequence (all zero at genesis)

const anchor = await signAnchor(
  { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:audit-log", sequence: 0, chainHash },
  current, { anchoredAt: 1_767_225_600 },
);
if (!anchor.ok) throw new Error(`signAnchor: ${anchor.error}`);

// Rotate: the current key signs the handover to the next key.
const transition = await signKeyTransition({
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:audit-log",
  effectiveAt: 1_767_312_000, nextKeyId: "audit-key-2", nextPublicKey: await next.publicKey(),
}, current);
if (!transition.ok) throw new Error(`signKeyTransition: ${transition.error}`);

const currentKey = { keyId: "audit-key-1", publicKey: await current.publicKey(), validFrom: 0, validBefore: null };
const nextKey = { keyId: "audit-key-2", publicKey: await next.publicKey(), validFrom: 1_767_312_000, validBefore: null };
const anchorFacts = verifyHistoricalAnchor(anchor.value.anchor, currentKey, {
  anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:audit-log", keyId: "audit-key-1",
  sequence: 0, anchoredAt: 1_767_225_600, chainHash, keyFingerprint: publicKeyThumbprintRaw(currentKey.publicKey),
});
const transitionFacts = verifyKeyTransition(transition.value.keyTransition, currentKey, nextKey, {
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:audit-log", effectiveAt: 1_767_312_000,
  currentKeyId: "audit-key-1", nextKeyId: "audit-key-2",
  currentKeyFingerprint: publicKeyThumbprintRaw(currentKey.publicKey),
  nextKeyFingerprint: publicKeyThumbprintRaw(nextKey.publicKey),
});
console.log(`anchor verifies: ${anchorFacts.ok}; transition verifies: ${transitionFacts.ok}`);
```

<!-- readme-output -->
```text
anchor verifies: true; transition verifies: true
```

On contract-major 2, `signV2Anchor` and `signV2KeyTransition` take the same inputs and the same
handle, and `v2.verifyHistoricalAnchor` and `v2.verifyKeyTransition` check them:

<!-- readme-sample: run -->
```ts
import { signV2Anchor, signV2KeyTransition } from "@bounded-authority-protocol/signer";
import { publicKeyThumbprintRaw, v2 } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const current = testKeyHandle("audit-key-1");
const next = testKeyHandle("audit-key-2");
const chainHash = new Uint8Array(32);

const anchor = await signV2Anchor(
  { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:audit-log", sequence: 0, chainHash },
  current, { anchoredAt: 1_767_225_600 },
);
const transition = await signV2KeyTransition({
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:audit-log",
  effectiveAt: 1_767_312_000, nextKeyId: "audit-key-2", nextPublicKey: await next.publicKey(),
}, current);
if (!anchor.ok || !transition.ok) throw new Error("signing failed");

const currentKey = { keyId: "audit-key-1", publicKey: await current.publicKey(), validFrom: 0, validBefore: null };
const nextKey = { keyId: "audit-key-2", publicKey: await next.publicKey(), validFrom: 1_767_312_000, validBefore: null };
const anchorFacts = v2.verifyHistoricalAnchor(anchor.value.anchor, currentKey, {
  anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:audit-log", keyId: "audit-key-1",
  sequence: 0, anchoredAt: 1_767_225_600, chainHash, keyFingerprint: publicKeyThumbprintRaw(currentKey.publicKey),
});
const transitionFacts = v2.verifyKeyTransition(transition.value.keyTransition, currentKey, nextKey, {
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:audit-log", effectiveAt: 1_767_312_000,
  currentKeyId: "audit-key-1", nextKeyId: "audit-key-2",
  currentKeyFingerprint: publicKeyThumbprintRaw(currentKey.publicKey),
  nextKeyFingerprint: publicKeyThumbprintRaw(nextKey.publicKey),
});
console.log(`v2 anchor verifies: ${anchorFacts.ok}; v2 transition verifies: ${transitionFacts.ok}`);
```

<!-- readme-output -->
```text
v2 anchor verifies: true; v2 transition verifies: true
```

To rotate a holder or issuer key, you also build a new handle: a handle reports one public key.

## Sign for a local app (loopback)

`signLocalLoopbackReport` signs the local-loopback application-proof profile
(`ba+loopback-proof`), for a desktop or local app that serves a protocol endpoint on the loopback
interface. The profile is selected by the function name, never inferred. The app issues a nonce,
the proof must carry it, and the target must be exactly `http://127.0.0.1[:port]/…` or
`http://[::1][:port]/…` (`localhost` and every other spelling are `producer_error`):

<!-- readme-sample: run -->
```ts
import { signGrant, signLocalLoopbackReport } from "@bounded-authority-protocol/signer";
import { checkLocalLoopbackHttpEnvelope, strUtf8, type Tagged } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const issuer = testKeyHandle("issuer-key-1", "issuer");
const helper = testKeyHandle("helper-key-1"); // an agent on the same machine

const grant = await signGrant({
  issuer: "https://issuer.example", grantId: "urn:example:grant:notes",
  audiences: ["https://notes.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_229_200,
  holderThumbprint: await helper.thumbprint(),
  operations: [{ name: "open_note", selectors: [{ kind: "all" }] }],
}, issuer);
if (!grant.ok) throw new Error(`signGrant: ${grant.error}`);

const nonce = "c8f2a1"; // issued by the local app for this request
const request = {
  method: "POST", targetUri: "http://127.0.0.1:47321/rpc",
  invocationId: "9c4b2e7a-1d3f-4c5b-a6e7-8f9a0b1c2d3e", operation: "open_note",
  castArguments: { t: "object", v: new Map<string, Tagged>([["title", { t: "string", v: strUtf8("Groceries") }]]) } satisfies Tagged,
};
const envelope = await signLocalLoopbackReport({ grantCompact: grant.value.grant, ...request, nonce }, helper, { issuedAt: 1_767_225_660 });
if (!envelope.ok) throw new Error(`signLocalLoopbackReport: ${envelope.error}`);

const facts = checkLocalLoopbackHttpEnvelope(envelope.value.grant, envelope.value.proof, {
  ...request,
  trustedIssuer: { keyId: "issuer-key-1", publicKey: await issuer.publicKey() },
  issuer: "https://issuer.example", audience: "https://notes.example",
  evaluationTime: 1_767_225_700, clockSkew: 60, proofMaxAge: 300,
  nonce: { kind: "required", value: nonce },
});
console.log(`loopback envelope verifies: ${facts.ok}`);
```

<!-- readme-output -->
```text
loopback envelope verifies: true
```

## Test your integration

- Use in-process handles like `key-handle.ts` above in tests; keep them out of production code.
- Verify what you sign with the verifier package (`checkEnvelope`, `verifyGrant`,
  `verifyHistoricalAnchor`, `verifyKeyTransition`, and the `v2` and `v3` namespaces), with the
  same expected values your resource server uses. A signer `ok` means the bytes were assembled and
  the signature matches the handle's key; only the verifier tells you the envelope verifies.
- Pin `issuedAt`, `proofId`, `anchoredAt` and the verifier's `evaluationTime` so the results do not
  depend on the clock.
- Assert the closed error codes for the cases you handle, for example `invalid_key_handle` for a
  holder handle passed to `signGrant`.
- If your handle reaches a remote custodian, test a `sign()` that rejects and one that signs with
  another key: both must give `signing_failed`.

## WebCrypto key handles

**New in 0.6.0, which is on npm only once the [Install](#install) line names it.** The published
0.5.0 does not have these factories; with 0.5.0, write a handle over WebCrypto yourself, the way
`key-handle.ts` in the [Quickstart](#quickstart) does over `node:crypto`.

Two factories build the handles above from a WebCrypto key pair whose private key is
**non-extractable**, so a page (or Deno, Bun or Node) signs with a key it cannot export.
`ed25519KeyHandle(pair, opts?)` returns a `KeyHandle`, `es256KeyHandle(pair, opts?)` an
`Es256KeyHandle`. `opts.keyId` (a non-empty string) adds `keyIdentity()` and `signingIdentity()`;
`opts.role` is `"holder"` (the default) or `"issuer"`. Each resolves a `SignerResult`: never a throw
or a rejection, and on any failure the value-free `invalid_key_handle`.

<!-- readme-sample: run-dom -->
```ts
import { ed25519KeyHandle, es256KeyHandle, signGrant, signV3Anchor } from "@bounded-authority-protocol/signer";

// You create the pair and own its lifetime; the library never generates, imports or exports a private key.
const issuerPair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
const issuer = await ed25519KeyHandle(issuerPair, { keyId: "issuer-key-1", role: "issuer" });
if (!issuer.ok) throw new Error(issuer.error);

const agentPair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
const agent = await ed25519KeyHandle(agentPair); // role "holder"
if (!agent.ok) throw new Error(agent.error);

const grant = await signGrant({
  issuer: "https://issuer.example", grantId: "urn:example:grant:calendar",
  audiences: ["https://calendar.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_232_800,
  holderThumbprint: await agent.value.thumbprint(),
  operations: [{ name: "create_event", selectors: [{ kind: "all" }] }],
}, issuer.value);

// Contract-major 3 (ES256): the same with an ECDSA P-256 pair.
const ledgerPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const ledger = await es256KeyHandle(ledgerPair, { keyId: "ledger-key-1" });
if (!ledger.ok) throw new Error(ledger.error);
const anchor = await signV3Anchor(
  { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:ledger", sequence: 0, chainHash: new Uint8Array(32) },
  ledger.value,
);

// An extractable private key is refused.
const exportable = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const refused = await ed25519KeyHandle(exportable);
console.log(`grant: ${grant.ok}; anchor: ${anchor.ok}; extractable pair: ${refused.ok ? "accepted" : refused.error}`);
```

<!-- readme-output -->
```text
grant: true; anchor: true; extractable pair: invalid_key_handle
```

The parameter type is structural: a DOM `CryptoKeyPair` and Node's `webcrypto.CryptoKeyPair` pass
without a cast. The sample above typechecks with the DOM library. One exception comes from the Node
types: `@types/node` (26.6.5) types `webcrypto.subtle.generateKey({ name: "Ed25519" }, ...)` as
`Promise<CryptoKey>`, so cast its result:

<!-- readme-sample: run -->
```ts
import { webcrypto } from "node:crypto";
import { ed25519KeyHandle } from "@bounded-authority-protocol/signer";

const pair = (await webcrypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as unknown as webcrypto.CryptoKeyPair;
const made = await ed25519KeyHandle(pair);
console.log(`handle: ${made.ok}`);
```

<!-- readme-output -->
```text
handle: true
```

**What the factory checks**, in this order. Any failure is `invalid_key_handle`, with no detail:

1. a secure context with `crypto.subtle` (on a plain-HTTP page there is none, and nothing you
   passed is read);
2. the options (`keyId` a non-empty string, `role` `"holder"` or `"issuer"`), read from the
   options object's own data properties only: an inherited `role` or `keyId`, including one on a
   polluted `Object.prototype`, is ignored. The pair's two keys are read the same way;
3. both keys are real `CryptoKey`s: every fact is read through the `CryptoKey.prototype`
   getters, never through `key.extractable`, and each key must be structured-cloneable (a
   `Proxy` never is), so a shadowed property, a plain object or a `Proxy` is refused. The clones
   run after the checks of steps 4 to 6, and the public key's after its raw export at step 7:
   WebKit on Linux terminates the page when it clones a raw-imported P-256 key with a bad point
   prefix, while that key's export fails cleanly. On Deno, where a `Proxy` can reach a key's
   internal slots, a `Proxy` that passes a private key off as the public one makes that export
   return private bytes; the factory zeroes its copy and the clone refuses the `Proxy`;
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
shared v3 path normalizes it to low-`s` and verifies it strictly, exactly as for your own handles.
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
- **The extractable refusal guards against accidents**, not against the key's holder. It
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
- **Retry key generation on WebKit for Linux.** WebKit 27.2 on Linux rejects about 1% of
  Ed25519 `generateKey` calls with an `OperationError` (measured: 19 of 2000; P-256: 0 of 2000).
  Generating the pair is your code, so retry that error a few times.
- **Other realms.** A key generated in a same-origin iframe, or generated in a dedicated worker
  and posted to the page, is accepted (the getters brand-check; there is no `instanceof` test); the
  browser lanes test both. Deno cannot hand a `CryptoKey` across realms: its structured clone of a
  `CryptoKey` is not a usable key, so generate keys where you sign.
- **Harden the page that holds a key:** the strict Content Security Policy described in
  [Browsers, Deno, Bun and workers](#browsers-deno-bun-and-workers), Trusted Types, Subresource
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

<!-- readme-sample: run -->
```ts
import { BACKEND_ID } from "@bounded-authority-protocol/verifier";

// "node" or "portable": which verifier backend this build resolved. Signing behaves the same in both.
console.log(BACKEND_ID);
```

The signer never touches private-key bytes: signing is always a handle's `sign()`, wherever and
however that handle is implemented. The only WebCrypto it uses is in the
[WebCrypto key handles](#webcrypto-key-handles) (**0.6.0**): `crypto.subtle.sign` with your
non-extractable `CryptoKey`, and `exportKey("raw")` of the public key.

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

Bundle size of the 0.6.0 source (esbuild, minified, browser target, tree-shaken from the package
entry, verifier included): every export 187 KB (51 KB gzip); `{ signReport }` 114 KB (31 KB gzip);
`{ signV2Report }` 111 KB (30 KB gzip); `{ signV3Report }` 69 KB (25 KB gzip). `pnpm size` prints
the current figures, and CI fails a change that takes any of them more than 10% past the first
measurement in [`tools/bundle-size-limits.json`](tools/bundle-size-limits.json).

## How this package is tested

- **Through the verifier, never a self-round-trip.** Every compact this library produces in CI is
  verified through the independent verifier package (`checkEnvelope`, `verifyGrant`,
  `verifyHistoricalAnchor`, `verifyKeyTransition`, the loopback profile's
  `checkLocalLoopbackHttpEnvelope`, and the `v2` and `v3` namespaces' equivalents). The v3
  signatures are also checked at the byte level: each verifies over the exact RFC 7515 signing
  input under `node:crypto`, both in the raw `ieee-p1363` form and re-encoded as DER.
- **Red-capable gates.** The issuer-role gate, the wrong-key guard, the loopback nonce and target
  rules, the identity-snapshot requirement, low-S normalization and the P-256 on-curve check each
  have a test that fails when the check is removed.
- **Every runtime.** One sign-then-verify battery (v1, loopback, v2 and v3 envelopes, grants,
  anchors and key transitions; a wrong-key handle on every major; 64 ES256 reports from a handle
  that emits high-`s` about half the time) runs on Node 22.23.1 and 24.19.0 with each verifier
  backend, on Deno 2.5.6 and Bun 1.3.14, and in Chromium, Firefox and WebKit through Playwright
  under the strict CSP. Every lane first asserts the verifier `BACKEND_ID` it expects. A lane on a
  non-secure origin, in each browser, checks the closed `producer_error` for a missing default
  `proofId` and that both key-handle factories refuse without touching their arguments.
- **WebCrypto key handles (0.6.0).** A key-handle battery runs in every one of those lanes with the
  engine's own keys: sign then verify on v1, v2 and v3, the extractable, type, algorithm, weak-key,
  mismatched-pair and relabeled-algorithm refusals, roles, the JWS-shape restriction, inherited and
  polluted options, `SubtleCrypto` methods patched after load, every signer with factory handles,
  and in the browsers an iframe key and a worker-posted key. Each lane records what its engine
  allows (key generation, signature widths, determinism, which weak keys import).
- **Browser safety.** A browser typecheck with no ambient types, lint rules (Node modules and
  globals, dynamic code, `@noble` and WebCrypto outside `src/webcrypto.ts`), a scan of the browser
  bundle for unresolved globals, and a typecheck of the packed tarball as a consumer installs it,
  with `skipLibCheck: false`.
- **Public types.** `test/exports.test.ts` fails if a public declaration names a type that the
  package root does not export.
- **The README.** Every TypeScript sample in this file is typechecked and run against the source by
  `test/readme.test.ts`, and each printed result is compared with the output shown under it; the
  handle and selector types are compared text for text with their declarations. `test/reader.ts`
  runs the Quickstart as a reader does, in an empty directory with the setup commands above, the
  pinned packages from npm and `npx tsx`, and checks that the pinned versions are npm's latest.

CI runs on Linux (`ubuntu-24.04`). Linux WebKit is evidence for this code on that WebKit build,
not for Safari. The release workflow repeats every lane on Node 24.19.0, then stages the publish
for a person to approve; packages are published with npm provenance.

## Versioning and compatibility

Package versions follow SemVer. Before 1.0 the minor position is the breaking boundary, so a caret
range such as `^0.5.0` never selects `0.6.0`. Compatibility with other implementations is governed
by the wire contract-majors this package signs (1, 2 and 3), not by package version numbers.

- **0.6.0** ([release status](#install)) adds the WebCrypto key handles, reads identity
  snapshots from own data properties only, and refuses a handle's off-curve P-256 key at resolution
  (`invalid_key_handle`, before `sign()`). It keeps the verifier at `^0.7.0`.
- **0.6.x** depends on the verifier `^1.0.0` and adds the WebCrypto key-handle factories.
- **0.5.x** depends on the verifier `^0.7.0`, runs in browsers, Deno and Bun, adds the
  contract-major-2 signers, and checks every ES256 signature with the verifier's strict
  `es256VerifyStrict` after low-S normalization.
- **0.4.x** depends on the verifier `^0.6.0` and refuses small-order and non-canonical Ed25519
  handles.
- **0.3.x** depends on the verifier `^0.5.0` and inherits its stricter identifier admission:
  identifiers with repeated fragment delimiters, raw brackets in userinfo or outside the authority,
  or malformed bracketed IPv6 hosts such as `http://[abc]/x` return `producer_error`.

The `"exports"` map keeps deep imports such as `@bounded-authority-protocol/signer/dist/src/v3.js`
resolving through a `"./*"` passthrough, but deep imports are not supported API and may close in a
future 0.x minor: import from the package root. Release notes are in [CHANGELOG.md](CHANGELOG.md).

## Protocol family

- [`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
  ([GitHub](https://github.com/baselabs/bounded_authority_protocol_typescript)): the verify side.
  This package depends on it, never the reverse. Its README's "Pairing with the signer" section
  shows the issuer, holder and resource roles with `signGrant`, `signReport` and `checkEnvelope`.
- [`baselabs/bounded_authority_protocol`](https://github.com/baselabs/bounded_authority_protocol):
  the protocol, with the wire specifications this package signs (`spec/bap-v1.md`,
  `spec/bap-local-loopback-http-v1.md`, `spec/bap-v2.md`, `spec/bap-v3.md`) and their design records.
- [`bounded_authority_report_adapter`](https://hex.pm/packages/bounded_authority_report_adapter)
  ([GitHub](https://github.com/baselabs/bounded_authority_report_adapter)): the Elixir signer this
  package ports.

## Development

```bash
pnpm install --frozen-lockfile
pnpm typecheck && pnpm build && pnpm lint && pnpm test
```

The repository pins Node 22.23.1 in [`.tool-versions`](.tool-versions); CI also runs Node 24.19.0.
The CI scripts:

| Script | What it checks |
|---|---|
| `typecheck`, `build` | strict typecheck; the `dist/` build |
| `typecheck:browser`, `typecheck:web` | `src/` with the DOM library and no ambient types; the playground |
| `lint`, `guard:browser` | the browser-safety lint rules; a scan of the browser bundle |
| `size` | the bundle-size limits |
| `test`, `test:portable` | unit tests, gates, the verifier oracle and the README samples, on the verifier's node and portable backends |
| `test:gates` | the red-capable gates alone |
| `test:runtimes` | the sign-then-verify lanes; `BAP_RUNTIMES` selects from `node,node-portable,deno,bun` (default: all four) |
| `test:tarball` | the packed package as a consumer installs it (needs Deno and Bun); the Quickstart as a reader runs it, the README's version pins, and the playground badge rules (these need the npm registry) |
| `test:browser` | Playwright lanes; `BAP_BROWSERS` selects from `chromium,firefox,webkit` (default `chromium`); install the engines with `pnpm exec playwright install` |
| `check:currency` | every dependency at its latest version, or pinned with a recorded reason |
| `build:site`, `guard:site` | the playground bundle, and its scan |

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
