---
title: "API reference"
category: Guides
---

# API reference


The [browsable API reference](https://baselabs.github.io/bounded_authority_signer_typescript/api/)
includes every public export and its TSDoc, with the package version in its title. The examples
below explain how to use those APIs together.

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
(see [WebCrypto key handles](webcrypto.md)), and these types: `KeyHandle`,
`Es256KeyHandle`, `KeyRole`, `AtomicKeyIdentity`, `AtomicSigningIdentity`, `SignerErrorCode`,
`SignerResult`, the input and option types named in this section, `SignerEvent`, `V2SignerEvent`,
`V3SignerEvent`, `V2OperationInput`, `V2SelectorInput`, `V3OperationInput` and
`V3SelectorInput` (see [Inputs](api-overview.md#inputs)), the value types `Envelope`, `GrantCompact`,
`AnchorCompact` and `TransitionCompact`, and `WebCryptoKeyLike`, `WebCryptoKeyPairLike` and
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
selector of an operation must match. The signer does not evaluate selectors; the verifier does. A
float-tagged selector value must have a fractional part (see
[Float-tagged integral selector values](errors.md#float-tagged-integral-selector-values)).

The operation and selector types: on v1 the verifier package's `OperationInput` and `SelectorInput`
(import them from `@bounded-authority-protocol/verifier`); on v2 `V2OperationInput` and
`V2SelectorInput`; on v3 `V3OperationInput` and `V3SelectorInput`, all exported from the package
root:

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
