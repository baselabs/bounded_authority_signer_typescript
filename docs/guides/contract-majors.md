---
title: "Choose a contract major"
category: Guides
---

# Choose a contract major

`@bounded-authority-protocol/signer@2.0.1` pairs with `@bounded-authority-protocol/verifier@2.0.1`. Package majors and wire contract majors are separate.
Select one wire major explicitly at both ends; there is no negotiation or permissive parser.

| Wire contract | Suite | Grant and proof | Verifier |
|---|---|---|---|
| 1 | Ed25519, 32-byte public key | `signGrant`, `signReport` | `checkEnvelope` |
| 2 | Ed25519, inclusive range selectors | `signV2Grant`, `signV2Report` | `v2.checkEnvelope` |
| 3 | ES256 P-256, 65-byte SEC1 public key | `signV3Grant`, `signV3Report` | `v3.checkEnvelope` |

Majors 2 and 3 support `all`, `equals`, `one_of`, `lte` and `gte`; major 1 supports the first three.
Every selector for an operation must hold. Numeric bounds must have the request value's type tag.
Integral numbers use `int`, including zero; `float` is for values with a fractional part.

All signatures returned by a handle are 64-byte Uint8Arrays. ES256 uses raw `r || s`, normalizes
high-S to low-S and refuses invalid scalars. DER needs [custody conversion](remote-custody.md).
[Local loopback](local-loopback.md) is a separate major-1 profile, selected by its function.
