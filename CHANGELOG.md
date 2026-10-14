# Changelog

## [0.6.0] — unreleased

WebCrypto key handles. Two factories build the existing handle types from a WebCrypto key pair
whose private key is non-extractable, so a browser page (or Deno, Bun or Node) can sign with a key
it cannot export. The library still never generates, imports, wraps, stores or exports a private
key: the caller creates the pair and owns its lifetime. Everything below is additive except the two
stricter handle checks under Changed: identity snapshots are read from own data properties only
(0.5.0 also read inherited ones, so an inherited `role: "issuer"` could sign a grant), and P-256 key
resolution (one error code changes).

### Added

- **`ed25519KeyHandle(pair, opts?)`** builds a `KeyHandle` (contract-majors 1 and 2, the sibling
  profiles) and **`es256KeyHandle(pair, opts?)`** an `Es256KeyHandle` (contract-major 3), with
  the structural types `WebCryptoKeyLike`, `WebCryptoKeyPairLike` and `WebCryptoHandleOptions`
  (`keyId` enables `keyIdentity()`/`signingIdentity()`; `role` is `"holder"` by default or
  `"issuer"`). No public declaration names a DOM or Node global type: a DOM `CryptoKeyPair` and
  Node's `webcrypto.CryptoKeyPair` pass without a cast.
- **What a factory checks**, in order, resolving the value-free `invalid_key_handle` on any failure
  and never throwing or rejecting: a secure context with `crypto.subtle` (nothing the caller passed
  is read before this); the options, from own data properties only (an inherited or polluted `role`
  or `keyId` is ignored); both keys, read once each from the pair's own data properties, are real
  `CryptoKey`s, read through the `CryptoKey.prototype` getters; private and public types; a
  non-extractable private key (always; no option allows an extractable one); `Ed25519`, or `ECDSA`
  on `P-256`, for both keys; both keys structured-cloneable (a `Proxy` never is, so one that lies to
  Deno's getters is refused too), the private key's clone after these checks and the public key's
  after its raw export, since WebKit on Linux terminates the page when it clones a raw-imported
  P-256 key whose point prefix is not `0x04` (its export fails cleanly); the raw public export (32
  bytes, acceptable and torsion-free; or the 65-byte uncompressed point on the curve); and one probe
  signature over a fixed message containing a zero byte (so it is never a JWS signing input),
  verified strictly against the exported key. The probe refuses a mismatched pair and a relabeled
  algorithm (an X25519 pair renamed Ed25519, a P-384 pair renamed P-256) at the factory.
  `crypto.subtle`, `SubtleCrypto.prototype.sign` and `exportKey`, the `CryptoKey` getters,
  `structuredClone` and `Reflect.apply` are captured when the module loads, so patching them later
  changes nothing.
- **The handle signs only JWS signing inputs.** `sign()` accepts only bytes of the shape
  `base64url "." base64url` and rejects anything else (inside the signers that is
  `signing_failed`). The ES256 handle returns WebCrypto's raw `r || s` unchanged, high-`s`
  included; the shared v3 tail normalizes it exactly as for a caller-written handle. The handle
  is frozen, its own keys are exactly its methods, and the private `CryptoKey` lives only in its
  closure. `sign()` takes a same-realm `Uint8Array` (the signers always pass one).
- README section "WebCrypto key handles" with the threat model: non-extractable stops export,
  not use; one key per purpose; non-extractable is a browser property only (on Node and Bun,
  `KeyObject.from(key).export()` returns the private key to any code in the process; Deno
  refuses); keys kept in IndexedDB live in the browser profile on disk; the extractable refusal
  is a guard against accidents, not against the key's own holder.

- **`V3OperationInput` and `V3SelectorInput` are exported from the package root.** `V3GrantInput`
  names them, but 0.5.0 exported neither, so a caller could only name them through a deep import.
  `test/exports.test.ts` now fails if any type that a public declaration reaches is not exported.

### Changed

- **Identity snapshots are read from own data properties only.** For every caller handle, the
  `role`, `keyId` and `publicKey` of a `keyIdentity()` or `signingIdentity()` snapshot are read
  from the snapshot's own data properties. An inherited field, a getter, or a role supplied by a
  polluted `Object.prototype` is `invalid_key_handle`. This changes behavior: 0.5.0 read inherited
  fields, so a snapshot without its own `role` could become an issuer through
  `Object.prototype.role`, and a snapshot whose fields sit on its prototype was accepted.
- **P-256 key resolution matches Ed25519's.** A caller handle that reports a 65-byte key that is
  not an uncompressed point on P-256 (`0x04 || x || y`, `x, y < p`, on the curve) is now
  `invalid_key_handle` at resolution, before `sign()` is called, on all four v3 signers. In 0.5.0
  it was resolved and failed later as `producer_error` (or, for `signV3Grant`, after `sign()` was
  called, as `signing_failed`).
- **Lint scope.** `src/webcrypto.ts` is the one file in `src/` that may reach `crypto.subtle`, and
  only for two direct calls: `subtle.sign(...)` and `subtle.exportKey("raw", ...)` with the literal
  `"raw"`. Its override is built from the same shared rule arrays as the rest of `src/`, so every
  other ban still applies there. Everywhere in `src/`, `sign` and `exportKey` may only be called
  directly (never read as a value, reached by a string key, destructured, or routed through
  `.call`, `.apply` or `.bind`), and `deriveBits`, `wrapKey`, `unwrapKey`, `encrypt`, `decrypt`
  and `digest` join the banned key-material names (also banned as strings). A computed member
  whose key is a concatenation or a template with expressions, and `String.fromCharCode` /
  `fromCodePoint`, are banned in `src/`. `src/webcrypto.ts` captures `sign` and `exportKey` only
  through `Object.getOwnPropertyDescriptor` and applies the captured `exportKey` only with the
  literal `"raw"`. `pnpm guard:browser` also scans `dist/src`
  for those names and for the private-key export formats `pkcs8`, `spki` and (in
  `webcrypto.js`) `jwk`.

### Tests

- One key-handle battery with real engine keys (no mocks) runs in every lane: Node 22.23.1 and
  24.19.0 (the unit suite and the runtime lanes, both verifier backends), Deno 2.5.6, Bun 1.3.14,
  and Playwright Chromium, Firefox and WebKit under the strict CSP, including a same-origin iframe
  key and a worker-posted key in the browsers, and every signer (all thirteen) with factory
  handles. Each lane records an engine capability row (key generation, signature
  widths, the high-`s` rate over 64 distinct inputs, whether ECDSA and Ed25519 are
  deterministic, whether weak or off-curve public keys import, whether the algorithm object can
  be relabeled, whether a structured-cloned key is usable). The non-secure-context lane now runs
  on all three engines and checks that both factories refuse without touching a recording Proxy
  passed as the pair and options. Per-lane expectations are explicit: a Proxy that flips
  symbol-keyed slots, which defeats the getter read on Deno, is refused in every lane by the
  structured-clone check, and `KeyObject.from()` exports a non-extractable key on Node and Bun but
  not on Deno.
- Type tests: DOM and Node pairs assign without a cast; under `@types/node` 26.6.5,
  `webcrypto.subtle.generateKey({ name: "Ed25519" }, ...)` is typed `Promise<CryptoKey>`, so its
  result needs `as unknown as webcrypto.CryptoKeyPair` (TS2345 without it; the README shows the
  cast). The packed tarball builds handles from each runtime's own keys and its ES2022-only
  typecheck has a red-proof for a declaration spelled with the DOM `CryptoKeyPair`.

### Documentation

- **README rewritten for a first run.** What the package is and is not, a table of contents, an
  install line naming the latest releases (signer 0.5.0, verifier 0.7.0) with what only 0.6.0 has
  marked, and a Quickstart that runs end to end from an empty directory: the setup commands (an ES
  module project, both packages, `tsx`), in-process key handles, a grant, a proof, and verification
  through the verifier package with each expected value explained. New sections: the exported handle
  types verbatim, an API reference (every signer, input, option and result), an error table with
  each code's meaning and fix, and guides for contract-majors 2 and 3, anchors and key rotation, the
  loopback profile, testing an integration, and the development scripts. The examples span code
  hosting, home automation, deployment, notes and calendars.
- **Every README sample runs.** `test/readme.test.ts` (part of `pnpm test` and `pnpm test:portable`)
  typechecks each TypeScript sample with the Node types or the DOM library, runs it against this
  source, compares what it prints with the output shown, compares the documented handle and
  selector types text for text with their declarations, and checks every README anchor that the
  README or a doc comment links to. `test/reader.ts` (part of `pnpm test:tarball`) runs the
  Quickstart as a reader does: an empty directory outside the repository, the README's setup
  commands verbatim, the pinned packages from npm (this repository's packed tarball only when the
  README pins the unpublished package.json version), `npx tsx`, and the output shown. It also
  fails when the README's signer pin is not npm's latest (or the package.json version with a release
  tag at HEAD), or its verifier pin is not npm's latest within the dependency range.
- **TSDoc on every export**: each signer's parameters, result and error codes, and each input and
  option field, with a link to the README example.
- **Corrections.** `castArguments` strings are UTF-8 bytes (`{ t: "string", v: Uint8Array }`); a
  grant's `expiresAt` must be after its `notBefore` (equal is `producer_error`); the verifier README's
  pairing example uses `signGrant` and `signReport`, not all five v1 signers; the WebCrypto battery's
  check count is no longer stated (the README said 104, Node runs 109); bundle sizes are re-measured
  on this source. The role gate is named in plain words everywhere: the issuer-role gate.
- `package.json` gains `keywords`.
- **Playground.** The demo is a support agent reading one ticket's record (it was a money transfer).
  The use-case cards keep one payments example, now the last card instead of the first. The hero and
  the first card say a grant names its operations and resources (a grant can name several of each),
  the just-in-time card leaves early withdrawal to the authority runtime's revocation, and the
  key-handle shape shows that every method may return a Promise.
- **Pages badge check.** The check compared the page's npm badge with `package.json`, which names a
  version before it is published, and had failed the Pages deploy on `main` since the 0.6.0 bump.
  `tools/check-site-badge.mjs` now passes a badge that names the latest npm release, or
  `package.json`'s version on a release commit (a `v<version>` tag at HEAD, read from `origin` so a
  shallow checkout sees it), since the release commit's deploy runs before the publish is approved. A
  registry outage fails closed with a message to rerun. `test/site-badge.ts` covers each state with
  real git repositories and the real and an unreachable registry.
- Source comments no longer use internal shorthand.

## [0.5.0] — 2026-10-13

Browser-safe builds and the contract-major-2 signers. The package now loads and runs in browsers,
Deno, Bun and workers with no `node:crypto`, no `Buffer` and no other Node API. The key-handle API
and every 0.4.0 export are unchanged; everything below is additive except the stricter ES256
post-sign check and the closed error for a missing default `proofId`.

### Added

- **The contract-major-2 signers**: `signV2Report`, `signV2Grant`, `signV2Anchor` and
  `signV2KeyTransition`, with the types `V2ReportInput`, `V2GrantInput`, `V2AnchorInput`,
  `V2TransitionInput`, `V2OperationInput`, `V2SelectorInput`, `V2SignOpts` and `V2SignerEvent`.
  Contract-major 2 had no signing surface in this package; these functions take the existing
  Ed25519 `KeyHandle` and compose through the verifier's public v2 signing inputs and
  `v2.assembleCompact`, so they emit exactly the verifier's v2 format (`v: 2`, `BAP2-*`
  separators, the `all`/`equals`/`one_of`/`lte`/`gte` selectors). The issuer-role gate, the wrong-key
  guard, the atomic identity snapshot and the weak-key refusal apply as on v1.
- An `"exports"` map (`"."`, `"./package.json"`, and a `"./*"` passthrough) and
  `"sideEffects": false`.
- Scripts: `typecheck:browser`, `lint`, `guard:browser`, `guard:site`, `size`, `test:portable`
  (the unit suite under the verifier's portable backend), `test:runtimes` (Node with both
  verifier backends, Deno, Bun), `test:tarball` and `test:browser` (Playwright).

### Changed

- **Strict ES256 post-sign check.** The v3 tail is sign, `normalizeLowS`, the verifier's
  `es256VerifyStrict`, assemble. The strict check refuses a high-`s` signature, so a missed or
  broken normalization fails closed as `signing_failed` instead of emitting a malleable
  signature. `normalizeLowS` refuses `r` or `s` outside `(0, n)`, and a handle returning such a
  value gets `signing_failed`. `node:crypto` and `Buffer` are gone from `src/`.
- **Handle and listener faults are contained, and handle buffers are copied.** `sign()` gets its
  own copy of the message, and the library checks and assembles from private copies of the
  message, the resolved public key and the returned signature. Before, a handle that rewrote
  the key array it had reported (any major), or the message buffer it was given (v3), could get
  `ok` for bytes the verifier rejects; it now gets `signing_failed`. A worker-style handle that
  transfers the message buffer now signs on v3 as on v1 and v2. `keyIdentity()` or
  `signingIdentity()` returning `null`, a throwing getter and a Proxy-wrapped key are
  `invalid_key_handle` instead of a thrown `TypeError`; an `onEvent` listener that throws is
  ignored and no longer changes the result.
- **Malformed operation entries** (`operations: [null]`, a `null` selector list or selector)
  are `producer_error` on v1, v2 and v3 alike.
- **Default `proofId` outside a secure context.** `crypto.randomUUID()` exists only in a secure
  context; on a plain-HTTP page the report signers called without `proofId` threw a
  `TypeError`. They now return the closed `producer_error`. An explicit `proofId` is unaffected.
- **Verifier lockstep 0.6.0 → 0.7.0**: the runtime dependency moves to
  `@bounded-authority-protocol/verifier` `^0.7.0` (before 1.0 the minor is the breaking
  boundary), the release that selects a portable crypto backend for browsers, Deno and Bun and
  exports `es256VerifyStrict` and `BACKEND_ID`. On Node.js the verifier keeps `node:crypto`.

### Deep imports

Deep imports such as `@bounded-authority-protocol/signer/dist/src/v3.js` keep resolving through the
`"./*"` passthrough, but they remain unsupported API and may be closed in a future 0.x minor; import
from the package root. In this release the internal `es256Verifies` (reachable only by deep import)
is the strict check, so it returns `false` for a high-`s` signature.

### Maintenance

- Guards, each with a red-proof against the real configuration: a browser typecheck
  (`tsconfig.browser.json`: DOM + ES2022, no ambient types, `skipLibCheck: false`); lint rules
  banning every Node built-in module and Node global (also through `globalThis`, `window` and
  `self`, and a `Buffer`, `process` or `require` property on any object, so a cast cannot hide
  it), network globals, dynamic `import()`, `eval`, implied eval, the `Function` constructor,
  `@noble`, `crypto.subtle` and key-generation entry points in `src/`; a scan of the browser bundle
  for unresolved globals and for `Buffer`, `process` or `require` read from a global object; a packed-tarball consumer typecheck under each resolution, library and
  condition set; and a bundle-size limit at the first measurement plus 10%.
- Lanes: one sign-then-verify battery runs on Node 22.23.1 and 24.19.0 with each verifier backend,
  Deno 2.5.6, Bun 1.3.14, and Playwright Chromium, Firefox and WebKit (CI, Linux only) under a
  strict CSP, plus a Chromium lane on a non-secure origin. Every lane asserts the verifier
  `BACKEND_ID` first.
- CI adds the guards, the size gate, the portable suite, the Node, Deno, Bun, tarball and browser
  lanes, and `npm audit signatures`. The release workflow is split: a verify job with read-only
  permissions runs every lane, and a publish job that alone holds the OIDC token (and needs the
  verify job) only installs without lifecycle scripts, builds, checks the tag and stages.
- The playground builds without the `node:crypto` shim and the `Buffer` polyfill (`web/shim/` is
  removed), and the Pages workflow scans its bundle before deploying. The `buffer`,
  `@noble/ed25519` and `@noble/hashes` dev dependencies are dropped; `@noble/curves`, `eslint`,
  `typescript-eslint`, `globals` and `playwright` join.
- TypeScript is pinned exactly to `"6.0.3"` (from 7.0.2; no range), matching the verifier:
  typescript-eslint 8.71.2 peers `typescript <6.1.0`, and the guard and tarball tests use the
  compiler API that 7.x no longer ships. Emitted JavaScript and declarations are identical apart
  from whitespace. The currency gate records the reason.

## [0.4.0] — 2026-10-13

Security advisory: [GHSA-wxxg-7cx6-m8qj](https://github.com/baselabs/bounded_authority_signer_typescript/security/advisories/GHSA-wxxg-7cx6-m8qj).

- **Refuse small-order and non-canonical Ed25519 key handles; strict self-verify.** A key
  handle whose public key is not an acceptable Ed25519 key (a small-order point, a
  non-canonical encoding, or a point off the curve) now returns `invalid_key_handle` from
  every Ed25519 signer before `sign()` is called. The post-sign self-check uses the
  verifier's strict Ed25519 verification instead of the runtime's. ES256 signers are
  unchanged.
- **Verifier lockstep 0.5.0 → 0.6.0**: the runtime dependency moves to
  `@bounded-authority-protocol/verifier` `^0.6.0` (before 1.0 the minor is the breaking
  boundary).
- CI runs the verify job on Node 22.23.1 and 24.19.0.

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
  `spec/bap-v3.md`). Four new signers — `signV3Grant`,
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
  composition to the verifier's producers is not yet adopted. Version-neutral algebra (JCS, JSON, base64url,
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
  low-S normalization, the wrong-key guard (ES256 form), the issuer-role gate (ES256
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

No library-code change — alignment with the protocol family as of September 17, 2026 (protocol
0.4.1, Elixir `bounded_authority_report_adapter` 0.6.2 and that adapter's pin move). The five-function surface is 1:1 with the
Elixir reference (compared against its `main` @ `d235a4a`: same signing table, profiles, bounds
flow, closed error set, and five-span telemetry) with zero signing-behavior delta since its
0.6.0; its 0.6.1 and 0.6.2 changed repository tooling and pins only.

- Dependency currency: the lockfile resolves `@bounded-authority-protocol/verifier` **0.2.2**
  (a verifier release with no library-code change; its 0.2.1 was its first provenance-bound
  release). The requirement
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
- Tri-platform CI (September 16, 2026): `ci.yml` gains `windows-latest` and `macos-latest`
  lanes beside `ubuntu-24.04` — every step is pnpm/Node, no POSIX shell. `.gitattributes`
  (`* text=auto eol=lf`) keeps a Windows autocrlf checkout byte-stable.
- Node toolchain identity: the repository pins its development toolchain — `.tool-versions`
  (`nodejs 22.23.1`, matching the Elixir family's pin) and
  the CI `node-version` move lockstep. `engines.node` stays the consumer floor `>= 22`; the
  release lane stays on Node 24 for the npm >= 11.5 that trusted publishing requires.
- README: the protocol-family cross-links land (verifier package by npm and repository, the
  protocol monorepo with its specs and ADRs, and the Elixir reference this package ports),
  and the contract-major statement is now explicit: this 0.1.x line signs **v1 only** (the
  verifier package's v2 surface is verify-side and unreachable from this library).

## [0.1.1] — 2026-09-14

- The first provenance-bound release: identical library content to 0.1.0 (which was
  published from a local terminal and carries no registry attestation), published through this repository's
  release workflow under npm trusted publishing — the workflow stages with a signed
  provenance statement and a human approves under 2FA. 0.1.0 is deprecated in favor of this
  version.

## [0.1.0] — 2026-09-14

- First release: the TypeScript port of the Elixir bounded_authority_report_adapter
  (tracked against its 0.6.0 / protocol 0.4.0). The five companion signers (report,
  local-loopback report, anchor, key transition, grant), the caller-owned key-handle
  contract with atomic identity snapshots, the issuer-role gate, the wrong-key
  signature guard, and the closed error-code set. All outputs oracle-verified through the
  independent @bounded-authority-protocol/verifier package in CI; closure gates are
  red-capable.
