# Changelog

## [0.3.1] — 2026-09-28

Documentation patch; no code or dependency change.

- README Quickstart: the example now checks each signer result before use (the 0.3.0 text
  read `.value` without checking `ok`, which does not compile under `strict`) and pins the
  proof's `issuedAt` inside the grant window. The example typechecks against the published
  0.3.0 and verifier 0.5.0 packages, and its output verifies through `checkEnvelope`.
- README: a Versioning and compatibility section (the pre-1.0 breaking boundary; 0.3.x
  inherits verifier 0.5.0's identifier admission and returns `producer_error` for the newly
  refused identifiers), and `spec/bap-v3.md` among the specifications this package signs.
- Playground: the signer table lists the four v3 signers; the grant card shows the wire
  `typ` `ba+cap` (it showed `ba+grant`).

## [0.3.0] — 2026-09-28

- **Verifier lockstep 0.4.1 → 0.5.0**: the runtime dependency moves to
  `@bounded-authority-protocol/verifier` `^0.5.0`. Before 1.0 the minor is the breaking
  boundary, and this move changes signer behavior: the verifier's producers now reject
  StringOrURI identifiers with repeated fragment delimiters, raw brackets in userinfo or
  outside authority, or malformed bracketed IPv6 hosts such as `http://[abc]/x`, so the
  signer refuses those inputs with its closed producer error instead of signing bytes the
  verifier would reject. Accepted identifiers keep their exact bytes. The verifier's new
  `contentAssertion` namespace is verify-side here; this signer does not yet produce
  content assertions.
- **TypeScript 7** (7.0.2) replaces 6.0.3 as the build compiler. Adoption met the former
  pin's criterion: emitted JavaScript and declarations are identical to 6.0.3 apart from
  whitespace, and typecheck, the unit/gates/oracle battery, and the site build pass. The
  pin is removed from the currency gate. `@types/node` moves to 26.6.3.
- CI runs on Linux only; macOS and Windows jobs are removed. Developer portability is
  unchanged. The playground badge now says so.

## [0.2.1] — 2026-09-24

- **Verifier lockstep 0.3.0 → 0.4.1** (the latest-first move): the dependency moves to
  `@bounded-authority-protocol/verifier` `^0.4.1`. The 0.4.x line is additive for this
  package — 0.4.0's `roleAttestation` namespace (the TS analog of the protocol's
  role-attestation release; this signer's attestation-gated grant signing is future work)
  and 0.4.1's producer/consumer bounds-agreement fix on `attestationSigningInput`
  (transferred from the protocol repository's 0.6.1 repair; no signer path emits through
  that producer yet). No signer code change: strict typecheck, the full unit/gates/oracle
  battery (every produced compact cross-verified through the verifier package's
  independent implementations), and the dependency-currency gate are green at 0.4.1, and
  the lockfile moves with the manifest. A fresh `npm install` of this package now resolves
  the verifier at 0.4.x — 0.2.0's `^0.3.0` caret excluded the 0.4 line entirely, the
  same-day-releases resolution-split class, live for two days.

## [0.2.0] — 2026-09-22

- **Contract-major 3 (`BAP3-ES256-SHA256`) producing-side adoption** (protocol
  [ADR 0035](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0035-es256-contract-major-activation.md),
  `spec/bap-v3.md`; the owner decision of 2026-09-20). Four new signers — `signV3Grant`,
  `signV3Report`, `signV3Anchor`, `signV3KeyTransition` — mirror the v1 functions under the
  ES256 suite: `alg: "ES256"` protected headers, payload `v: 3`, the `BAP3-REQUEST\0` digest
  prefix, the EC proof JWK `{crv, kty, x, y}` with the RFC 7638 EC thumbprint as `cnf.jkt`,
  the five-kind selector algebra (`all`, `equals`, `one_of`, `lte`, `gte`), 65-byte
  uncompressed-SEC1 raw public keys, and 64-byte raw `r || s` signatures. The v3 key-handle
  contract (`Es256KeyHandle`) keeps the same custody boundary with the suite's widths; the
  local-loopback profile stays contract-major-1-bound (no v3 form exists).
- **Low-S normalization is load-bearing** (spec/bap-v3.md §3.2; `REQ3-SIGNING-low-s`): the
  shared v3 signing tail normalizes every handle signature before emission — `s ← n − s`
  when high, one conditional subtraction — so the emitted `s` satisfies `0 < s ≤ (n−1)/2`
  always. The retained property run (120 fresh P-256 keys through `signV3Report`) observed
  natural high-S at the expected ~1/2 rate, every emitted signature verifying under
  node:crypto both in the raw `ieee-p1363` form and re-encoded as DER.
- The v3 producing profile lives in this repository (`src/v3.ts`): the verifier package's
  0.3.0 release now ships its v3 verify surface, but the v1 pattern of delegating
  composition to the verifier's producers is not yet adopted — that switch remains an
  owner-gated decision recorded here. Version-neutral algebra (JCS, JSON, base64url,
  SHA-256, typed projection, URI normalization, Bounds) single-sources from the verifier
  package's exported primitives; only the v3-specific bytes are authored here. The
  dependency moves to `@bounded-authority-protocol/verifier` `^0.3.0` (the lockstep
  latest-first move onto the verifier's ES256 release), and the v3 test oracle —
  crypto-level while the verifier package lacked a v3 surface — now cross-verifies through
  the verifier package's `v3` namespace (`v3.verifyGrant`, `v3.checkEnvelope`,
  `v3.verifyHistoricalAnchor`, `v3.verifyKeyTransition`) per this repository's
  no-self-round-trip evidence rule, with the crypto-level signature pinning retained as
  byte-level composition evidence.
- The v3 closure gates are red-capable (proven at authoring by mechanical removal):
  low-S normalization, the wrong-key guard (ES256 form), the C1 issuer-role gate (ES256
  form), and the producer's P-256 on-curve/width check each redden exactly their leg.
- Dependency currency (the latest-first gate): in-range lockfile updates discovered by
  running the gate — `@types/node` 26.6.2, `tsx` 4.23.15 (never pinnable, in-range drift).
- The repository's GitHub Pages site is live — the envelope playground
  (https://baselabs.github.io/bounded_authority_signer_typescript/): a landing page pitched
  at MCP/OAuth audiences plus a fully in-browser demo bundling this package and the published
  verifier package (real signatures, real verification, tamper deck, wire viewer; keys
  generated in the visitor's browser never enter the library). The npm `homepage` field now
  points there; the README links it at the top. No library-code change.

## [0.1.2] — 2026-09-18

No library-code change — alignment with the protocol family's 2026-09-17 state (BAP 0.4.1,
Elixir BARA 0.6.2 + the pin move). The five-function surface is 1:1 with the Elixir
reference (compared against its `main` @ `d235a4a`: same signing table, profiles, bounds
flow, closed error set, and five-span telemetry) with zero signing-behavior delta since
0.6.0 — BARA 0.6.1/0.6.2 and its Unreleased entries are repository tooling and pins only.

- Dependency currency: the lockfile resolves `@bounded-authority-protocol/verifier` **0.2.2**
  (the verifier's family-alignment release — itself no library-code change; first 0.2.0 →
  0.2.1 provenance-bound, then 0.2.2 after its own alignment session). The requirement
  deliberately holds the caret `^0.2.0` — an exact pin in a published package's dependencies
  would force every consumer's resolution and block dedupe, and reproducibility is already
  provided by the tracked lockfile plus CI's `--frozen-lockfile` installs.
- Dependency-currency gate (latest-first, the family ADR 0032 shape): `tools/check-currency.mjs`
  ported byte-identical from the verifier package's repository — `pnpm outdated` data
  classified through the canonical `semver` resolver: in-range resolvable drift fails (never
  pinnable), deliberate pins cover only out-of-range latests and carry inline reasons
  (typescript stays on 6.x pending the 7.x native-compiler review), and an unverifiable
  currency state fails closed. Wired as `pnpm check:currency` and a CI `dependency-currency`
  job; four legs re-proven on this repository (green real lock / red pin-removed / red
  unreachable registry / green all-current scratch). Dev dependencies at latest:
  `@types/node` 26.6.1, `semver` 7.8.5 (the gate's resolver).
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
