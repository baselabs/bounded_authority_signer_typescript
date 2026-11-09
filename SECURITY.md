# Security policy

## Reporting a vulnerability

Report a vulnerability privately through GitHub: open this repository's **Security** tab and choose
**Report a vulnerability** (or go to
<https://github.com/baselabs/bounded_authority_signer_typescript/security/advisories/new>).
Private vulnerability reporting is enabled for this repository. Do not open a public issue, pull
request or discussion that contains an exploit, a private key, a credential, production data or
details of an unfixed vulnerability.

A useful report names the affected package version or commit, the property that breaks (for example
"a grant is signed with a key other than the handle's", or "an error carries key material"), a
minimal reproduction that uses generated keys and no production data, and the outcome you expected.
We acknowledge, triage and fix through the private advisory and coordinate disclosure there.

A vulnerability in what this package depends on belongs to that project's own private reporting:
the verifier package at
<https://github.com/baselabs/bounded_authority_protocol_typescript/security/advisories/new>, and the
protocol itself (the specification, the conformance corpora, or the Elixir reference) at
<https://github.com/baselabs/bounded_authority_protocol/security/advisories/new>.

## Supported versions

The latest published release line of `@bounded-authority-protocol/signer` on npm (the line of its
`latest` tag) is supported, and fixes land only on that line.

Earlier releases fall into two groups:

- Releases before 0.4.0 accept small-order and non-canonical Ed25519 key handles. They are
  deprecated on npm with a pointer to the advisory
  [GHSA-wxxg-7cx6-m8qj](https://github.com/baselabs/bounded_authority_signer_typescript/security/advisories/GHSA-wxxg-7cx6-m8qj).
- Releases before 2.0.0 (unreleased) predate the selector float-zero repair (the protocol's
  erratum 6): they sign a grant whose selector value holds a float-tagged integral number, which
  the verifier reads back integer-tagged. Every affected value sits inside issuer-signed bytes, so
  under the protocol's governance (§ Soundness repairs) the repair has no advisory: the
  [errata registry](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/errata.md)
  entry is the disclosure, and those releases stay installable and are not deprecated. See
  [Float-tagged integral selector values](README.md#float-tagged-integral-selector-values).

Upgrade to the latest release.

## What the package does and does not do

The package assembles and signs protocol artifacts through a key handle you supply, and checks
every signature against the handle's public key before it returns the artifact. It never holds,
generates, imports or exports a private key, does not verify an artifact for a resource server (the
verifier package does), and does not decide whether a request is allowed, store keys, or track
replay and revocation; those belong to your authority runtime. A report about a key handle you
wrote, or the custodian behind it, is about that handle, not this package. A report that the
package signs with a key other than the handle's, returns an artifact its own checks should have
refused, or puts key material, nonce values or report content into an error or event, is about
this package.

Releases from 0.1.1 on are published from this repository's release workflow through npm trusted
publishing with provenance; `npm audit signatures` verifies the registry signatures and attestations
of an install.
