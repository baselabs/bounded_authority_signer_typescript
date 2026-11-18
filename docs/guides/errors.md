---
title: "Errors"
category: Guides
---

# Errors


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
| `producer_error` | every signer | the protocol refused an input: a non-UUID `invocationId`, a malformed identifier or URI, no audiences or operations, `expiresAt` not after `notBefore`, a negative `sequence`, an exceeded bound, a selector value holding a float-tagged integral number (`0.0`, `-0.0`, `10.0`; see [below](errors.md#float-tagged-integral-selector-values)), a loopback target other than `127.0.0.1` or `[::1]` over `http`; or no `proofId` could be generated | correct the value (an integral selector value is an `int`); pass `proofId` on a plain-HTTP page |

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

### Float-tagged integral selector values

The grant signers `signGrant`, `signV2Grant` and `signV3Grant` return
`producer_error`, before `sign()` is called, when a selector value holds a float-tagged number with
no fractional part (`{ t: "float", v: 30 }`, which is how `30.0`, `-0.0` and an underflowing
`1e-400` arrive), at any depth: an `equals` value, a `one_of` member, or an `lte` or `gte` bound.
Canonical JSON (RFC 8785) writes such a number as integer text, which decodes integer-tagged, so the
signed grant would not carry the value it was given. Write an integral value as an `int`; a float
with a fractional part signs as before. This is the producer side of the protocol's
[erratum 6](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/errata.md); the
report, anchor and key-transition signers are unchanged. 1.0.0 signed these grants, and the verifier read their values back as integers.

Here a backup agent may keep snapshots for at most 30 days:

<!-- readme-sample: run -->
```ts
import { signGrant, signV2Grant, signV3Grant } from "@bounded-authority-protocol/signer";
import type { Tagged } from "@bounded-authority-protocol/verifier";
import { testEs256KeyHandle, testKeyHandle } from "./key-handle.js";

const issuer = testKeyHandle("backup-issuer-1", "issuer");
const es256Issuer = testEs256KeyHandle("backup-issuer-2", "issuer");
const agent = testKeyHandle("backup-agent-1");

const base = {
  issuer: "https://backup.example", grantId: "urn:example:grant:retention",
  audiences: ["https://snapshots.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_312_000,
  holderThumbprint: await agent.thumbprint(),
};
const days = (value: Tagged) => ({ path: ["days"], value });
const results = {
  "signGrant, equals 30.0": await signGrant({ ...base, operations: [{ name: "set_retention", selectors: [{ kind: "equals", ...days({ t: "float", v: 30.0 }) }] }] }, issuer),
  "signV2Grant, lte 30.0": await signV2Grant({ ...base, operations: [{ name: "set_retention", selectors: [{ kind: "lte", ...days({ t: "float", v: 30.0 }) }] }] }, issuer),
  "signV3Grant, lte 30.0": await signV3Grant({ ...base, operations: [{ name: "set_retention", selectors: [{ kind: "lte", ...days({ t: "float", v: 30.0 }) }] }] }, es256Issuer),
  "signV3Grant, lte 30 (int)": await signV3Grant({ ...base, operations: [{ name: "set_retention", selectors: [{ kind: "lte", ...days({ t: "int", v: 30 }) }] }] }, es256Issuer),
  "signV3Grant, lte 30.5": await signV3Grant({ ...base, operations: [{ name: "set_retention", selectors: [{ kind: "lte", ...days({ t: "float", v: 30.5 }) }] }] }, es256Issuer),
};
for (const [label, result] of Object.entries(results)) console.log(`${label}: ${result.ok ? "signed" : result.error}`);
```

<!-- readme-output -->
```text
signGrant, equals 30.0: producer_error
signV2Grant, lte 30.0: producer_error
signV3Grant, lte 30.0: producer_error
signV3Grant, lte 30 (int): signed
signV3Grant, lte 30.5: signed
```
