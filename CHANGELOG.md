# Changelog

## [Unreleased]

No library-code change — alignment with the protocol family's 2026-09-17 state (BAP 0.4.1,
Elixir BARA 0.6.2 + the pin move). The five-function surface is 1:1 with the Elixir
reference (compared against its `main` @ `d235a4a`: same signing table, profiles, bounds
flow, closed error set, and five-span telemetry) with zero signing-behavior delta since
0.6.0 — BARA 0.6.1/0.6.2 and its Unreleased entries are repository tooling and pins only.

- Dependency currency: the lockfile resolves `@bounded-authority-protocol/verifier` 0.2.0 →
  **0.2.1** (the provenance-bound re-release; content-identical to 0.2.0). The requirement
  deliberately holds the caret `^0.2.0` — an exact pin in a published package's dependencies
  would force every consumer's resolution and block dedupe, and reproducibility is already
  provided by the tracked lockfile plus CI's `--frozen-lockfile` installs.
- Tri-platform CI (family bar, 2026-09-16): `ci.yml` gains `windows-latest` and `macos-latest`
  lanes beside `ubuntu-24.04` — every step is pnpm/Node, no POSIX shell. `.gitattributes`
  (`* text=auto eol=lf`) keeps a Windows autocrlf checkout byte-stable.
- Node toolchain identity: the repository pins its development toolchain — `.tool-versions`
  (`nodejs 22.23.1`, matching the Elixir family's pin after the PATH-shadowing incident) and
  the CI `node-version` move lockstep. `engines.node` stays the consumer floor `>= 22`; the
  release lane stays on Node 24 for the npm >= 11.5 that trusted publishing requires.
- README: the protocol-family cross-links land (verifier package by npm and repository, the
  protocol monorepo with its specs and ADRs, and the Elixir reference this package ports),
  and the contract-major statement is now explicit: this 0.1.x line signs **v1 only** (the
  verifier package's v2 surface is verify-side and unreachable from this library).

## [0.1.1] — 2026-09-14

- The first provenance-bound release: identical library content to 0.1.0 (which was
  terminal-seeded and carries no registry attestation), published through this repository's
  release workflow under npm trusted publishing — the workflow stages with a signed
  provenance statement and a human approves under 2FA. 0.1.0 is deprecated in favor of this
  version.

## [0.1.0] — 2026-09-14

- First release: the TypeScript port of the Elixir bounded_authority_report_adapter
  (tracked against its 0.6.0 / protocol 0.4.0). The five companion signers (report,
  local-loopback report, anchor, key transition, grant), the caller-owned key-handle
  contract with atomic identity snapshots, the C1 issuer-role gate, the wrong-key
  signature guard, and the closed error-code set. All outputs oracle-verified through the
  independent @bounded-authority-protocol/verifier package in CI; closure gates are
  red-capable.
