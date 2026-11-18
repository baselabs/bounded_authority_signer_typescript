---
title: "How this package is tested"
category: Guides
---

# How this package is tested


- **Through the verifier, never a self-round-trip.** Every compact this library produces in CI is
  verified through the independent verifier package (`checkEnvelope`, `verifyGrant`,
  `verifyHistoricalAnchor`, `verifyKeyTransition`, the loopback profile's
  `checkLocalLoopbackHttpEnvelope`, and the `v2` and `v3` namespaces' equivalents). The v3
  signatures are also checked at the byte level: each verifies over the exact RFC 7515 signing
  input under `node:crypto`, both in the raw `ieee-p1363` form and re-encoded as DER.
- **Red-capable gates.** The issuer-role gate, the wrong-key guard, the loopback nonce and target
  rules, the identity-snapshot requirement, low-S normalization and the P-256 on-curve check each
  have a test that fails when the check is removed.
- **Every runtime.** One sign-then-verify battery (v1, loopback, v2 and v3 envelopes, grants,
  anchors and key transitions; a wrong-key handle on every major; 64 ES256 reports from a handle
  that emits high-`s` about half the time) runs on Node 22.23.1 and 24.19.0 with each verifier
  backend, on Deno 2.5.6 and Bun 1.3.14, and in Chromium, Firefox and WebKit through Playwright
  under the strict CSP. Every lane first asserts the verifier `BACKEND_ID` it expects. A lane on a
  non-secure origin, in each browser, checks the closed `producer_error` for a missing default
  `proofId` and that both key-handle factories refuse without touching their arguments.
- **WebCrypto key handles.** A key-handle battery runs in every one of those lanes with the
  engine's own keys: sign then verify on v1, v2 and v3, the extractable, type, algorithm, weak-key,
  mismatched-pair and relabeled-algorithm refusals, roles, the JWS-shape restriction, inherited and
  polluted options, `SubtleCrypto` methods patched after load, every signer with factory handles,
  and in the browsers an iframe key and a worker-posted key. Each lane records what its engine
  allows (key generation, signature widths, determinism, which weak keys import).
- **Browser safety.** A browser typecheck with no ambient types, lint rules (Node modules and
  globals, dynamic code, `@noble` and WebCrypto outside `src/webcrypto.ts`), a scan of the browser
  bundle for unresolved globals, and a typecheck of the packed tarball as a consumer installs it,
  with `skipLibCheck: false`.
- **Public types.** `test/exports.test.ts` fails if a public declaration names a type that the
  package root does not export.
- **Documentation.** Recursive CommonMark sample discovery includes guides, TSDoc and the site.
  Every executable sample has asserted output. Reader runs use explicit candidate and published
  modes; published mode installs exact registry artifacts and typechecks their declarations.
  Browser samples run in each real engine. Deno notebooks execute cell by cell in a fresh Jupyter
  kernel, with persisted semantic output comparison and residue checks.

CI runs on Linux (`ubuntu-24.04`). Linux WebKit is evidence for this code on that WebKit build,
not for Safari. Qualification runs every lane before a release commit lands. The owner then
dispatches `publish.yml` from the default branch in environment `publish`. It installs the exact
`.tool-versions` runtime and declared pnpm with frozen dependencies, refuses an already published
or tagged version, builds the library and API docs, packs and inspects one archive, records and
checks its SHA-256, and stages those bytes with `npm stage publish --provenance`. It does not
rerun qualification or create a tag.

The publication workflow publishes new versions of existing npm packages only and
refuses a package name the registry has never had. A first publication is the owner's decision.

Staging success is not publication: the owner approves the version on npmjs.com. Infra reads
the publication back and tags the published commit. The owner then dispatches `pages.yml` from
the default branch in environment `github-pages`; it rebuilds the site from that branch and
the API reference from the tag matching npm latest. Registry or Pages read failures fail closed.
