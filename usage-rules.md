---
title: "Signer usage rules"
category: Package policies
---

# Signer usage rules

- Import from `@bounded-authority-protocol/signer`; deep paths are closed.
- Pair `@bounded-authority-protocol/signer@2.0.1` with `@bounded-authority-protocol/verifier@2.0.1` in examples. Choose a wire major explicitly at both ends.
- Keep private key bytes in caller-owned custody; give the package a handle, public keys and signatures.
- Grants require an atomic issuer-role signing identity; role is not externally trusted authority.
- Ed25519 uses 32-byte public keys and 64-byte signatures. ES256 uses 65-byte uncompressed P-256
  public keys and 64-byte raw `r || s`. Convert DER in the custody implementation.
- Never bypass a wrong-key or weak-key refusal. Build a new handle on rotation.
- Integral selector numbers use `int`; non-integral numbers use `float`.
- Pass the actual method, canonical target URI, operation, invocation ID and typed arguments.
- Check `ok` on every result. Errors contain no partial artifact. Never log compacts or secrets.
- Select loopback explicitly and supply its server-issued nonce and literal loopback target.
- Use verified facts only as input to the host's trust, policy, revocation and atomic replay checks.
- Browser verification is display-only. Non-extractable keys can still be used by scripts in their origin.
- The host owns retries, transport, deadlines, storage, key lifecycle, authorization and effects.

See [guides](README.md#documentation), [security](SECURITY.md) and [upgrading](docs/guides/upgrading.md).

Candidate notebook and consumer journeys install this repository's package from the packed candidate.
`publish.yml` waits up to ten minutes in the upload job for npm to serve the exact inspected
archive. Pending owner approval fails that run clearly; dispatch the same commit after approval.
The keyless `published-notebooks` job runs only after byte-for-byte registry read-back succeeds.
A maintainer can run `pnpm notebooks:published` and `pnpm docs:checks:published` on demand
once that version is available. The upload job and its environment gate are separate.
