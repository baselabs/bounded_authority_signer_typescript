---
title: "Concepts and trust boundaries"
category: Guides
---

# Concepts and trust boundaries

An issuer signs a grant naming a holder key thumbprint, audiences, validity window and operations.
A holder signs a proof over the exact grant and request. A resource verifies that envelope against
its own trusted issuer key and the request it actually received. A signing result is an artifact;
a verification result is a set of facts. Neither is a host authorization decision.

Selectors constrain typed arguments, not application objects. The host derives and casts arguments
before signing or verifying: strings are UTF-8 bytes, objects are Maps, integers and fractional
numbers have distinct tags. See [API inputs](api-overview.md#inputs).

An invocation ID identifies a logical invocation; a proof ID identifies a proof. The signer does
not reserve either. Regenerating a proof does not make a replay safe. The resource owns atomic
replay reservation, live revocation, policy and any effect transaction.

A key identity is one atomic snapshot of a key ID and public key. An issuer identity adds a role.
Role is a local guard against accidental use of a holder handle. It does not confer external trust:
the resource chooses trusted keys independently. See [key custody](key-custody.md).

An anchor checkpoints a chain hash. A transition describes a handover between keys; it cannot
update anyone's trusted-key store. Historical verification uses explicit validity intervals and
expected fingerprints. See [rotation](rotate-keys.md).
