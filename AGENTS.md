# Working on the signer

This repository is the public npm package `@bounded-authority-protocol/signer`. Read
[CONTRIBUTING.md](CONTRIBUTING.md), [usage-rules.md](usage-rules.md), [SECURITY.md](SECURITY.md)
and the public API before changing it. Documentation is under `docs/guides/` and `docs/notebooks/`.

Keep signing in caller-owned custody. Do not add authorization, replay or revocation state.
Import only public verifier APIs. No private key bytes, secret fixtures, product vocabulary or
private infrastructure references enter the package. Use real keys and services in tests.

Never run builds, tests, TypeScript, Deno, Jupyter or documentation generators on the owner's
Mac. Qualification runs in GitHub CI on ubuntu-24.04. Edit, inspect and commit locally; the
maintainer owns qualification landing. Stage named paths; never stash, rewrite history,
force-push, publish, tag, dispatch workflows or change release credentials.

Preserve owner-dispatched publication and Pages triggers, environments and keys. CI runs only on
`kci/**`; every job is required by the last `qualified` job. Actions are pinned to full commits,
checkout disables persisted credentials, tool versions are strict and installs are frozen.
Do not use organization secrets or variables in public CI.
