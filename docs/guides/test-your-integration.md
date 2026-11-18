---
title: "Test your integration"
category: Guides
---

# Test your integration


- Use in-process handles like [`key-handle.ts` in the quickstart](getting-started.md#quickstart) in tests; keep them out of production code.
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


Exercise the real custody path you will deploy, including key rotation between attempts. Assert
all of the following at the resource boundary: a valid request verifies; changed method, URI,
operation or typed arguments refuses; an expired grant and a different holder refuses; a selector
outside the grant refuses even when the proof is correctly signed. For remote custody, run the
[signature-encoding journey](remote-custody.md) and the [custody notebook](../notebooks/key-custody.ipynb).
Never turn a failed custody check into a permissive fallback.

Keep protocol tests and operational tests explicit. Verify raw credentials under independently
configured trusted keys, time and expected context. Separately test the host's authorization,
revocation and atomic replay reservation against its actual backing services. No signer or pure
verifier test establishes those host guarantees. The [HTTP recipe](recipes.md#node-http-client)
executes a real transport request and a changed-target refusal. The [playground](https://baselabs.github.io/bounded_authority_signer_typescript/)
exercises all suite and custody paths in real engines; it remains display-only.
