---
title: "Security for integrators"
category: Guides
---

# Security for integrators

Read [SECURITY.md](../../SECURITY.md) for reporting and supported package lines.
Never send a caller's verified facts as execution authority. A trusted resource or authority runtime
must accept raw credentials and reconstruct the expected method, URI, invocation ID, operation
and typed arguments from the actual request. It selects trusted issuer keys, checks live revocation,
reserves replay atomically and applies policy before an effect.

A holder cannot grant itself trusted issuer status by setting its handle role to `issuer`. The
issuer-role guard checks caller-supplied structure; resource trust is configured separately.
A signer does not authenticate an input grant or check its selectors. Verify the envelope at the
resource with the matching wire-major verifier.

Keep keys separate by purpose. WebCrypto handles accept any JWS-shaped signing input, not only
BAP. Non-extractability limits export, not key use by another script in the origin. XSS, malicious
dependencies and extensions can sign if they can reach the key. In Node and Bun, in-process code
can export a non-extractable CryptoKey through Node crypto facilities. Use appropriate remote or
hardware custody where process isolation is required. The library makes no hardware attestation.

Use short grants, narrow selectors, exact audiences and HTTPS. Loopback accepts literal IPs and a
required server nonce, not `localhost`. Do not log compacts, arguments, nonce values or custody
responses. In-page verification is display-only. See [WebCrypto](webcrypto.md) for the engine
boundary and [operations](operations.md) for custody failures and retries.
