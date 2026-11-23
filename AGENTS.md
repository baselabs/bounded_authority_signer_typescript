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
checkout disables persisted credentials and installs are frozen. Runtime defaults and compatibility
lanes come only from the executable shared reader at `scripts/toolchain.sh`. Pass its outputs to
setup actions, then use `--installed` immediately after each setup to refuse a different installed
Node, Deno, Bun, Python or uv version under the same condition. Keep the shared reader byte-identical.
Do not use organization secrets or variables in public CI.

The `site` qualification job runs `pnpm site --source=commit` from a frozen install, before
any library build. CI exports HEAD, builds the API with that export's own frozen TypeDoc, and
checks version claims against the committed package version, without querying this package's
registry metadata or release tags. Pages runs the same ordered pipeline with `pnpm site`:
typecheck and build the playground, scan the browser bundle, build and check the API from the
npm-latest release tag, and check claims against npm latest. Both sources fail closed if their
separate frozen install has no TypeDoc.
