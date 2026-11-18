---
title: "Versioning and compatibility"
category: Guides
---

# Versioning and compatibility


Package versions follow SemVer: a breaking change costs a major version, and a caret range such as
`^2.0.0` carries every later minor and patch. Compatibility with other implementations is governed
by the wire contract-majors this package signs (1, 2 and 3), not by package version numbers. A
package major is not a contract-major: no wire format changes with one, and every artifact names its
own contract-major (payload `v`, the `BAP<n>-…` suite, the major-bound domain separators).

- **2.0.0** carries the protocol's erratum 6: `signGrant`, `signV2Grant` and
  `signV3Grant` refuse a float-tagged integral selector value that 1.0.0 signed (see
  [Float-tagged integral selector values](errors.md#float-tagged-integral-selector-values)). Refusing an
  input that 1.0.0 accepted is breaking under the 1.0 contract, so it is a major. It depends on the
  verifier `^2.0.0`, the verifier release that carries the same erratum. 1.0.0 stays installable
  and keeps signing such grants.
- **From 2.x on, a soundness repair is a minor.** A soundness repair is the protocol's narrow
  verdict correction under
  [its governance](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/governance.md#soundness-repairs):
  it only turns accepts into rejects, only for inputs no conforming producer emits, and changes no
  verdict of any certified conformance corpus; the protocol's
  [errata](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/errata.md) record
  each one. The release that carries one is a minor, so a caret range receives it. Every other
  breaking change still costs a major.
- **1.0.0** closed deep imports: the exports map exposes the package root and `./package.json`
  only, so import from the package root.

Before 1.0 the minor position was the breaking boundary. Every release's changes are in
[CHANGELOG.md](../../CHANGELOG.md).


## Supported migration routes

From package 1.x, pair signer 2.0.0 with verifier 2.0.0 and replace float-tagged integral
selector values with `int`. The [error guide](errors.md#float-tagged-integral-selector-values)
executes both the refused old shape and accepted replacement on every grant signer.

For pre-1.0 installations, first replace deep imports with package-root imports. The exports map
permits only the root and package.json. Replace weak/noncanonical Ed25519 keys with freshly
provisioned acceptable keys, and reissue holder-bound grants when their holder key changes.
Do not convert a failed key check into a permissive parser. Existing artifacts remain in their
original wire major; select the matching verifier until you explicitly reissue on another major.

The executed migration checks below cover deep-import closure and weak-key refusal. These are
current-package checks of the earlier integration shapes, not an assertion that an old package
is installed. No supported earlier major requires a different migration path.

<!-- readme-sample: run -->
```ts
import { signAnchor } from "@bounded-authority-protocol/signer";
import { testKeyHandle } from "./key-handle.js";
const identity = new Uint8Array(32); identity[0] = 1;
const weak = { sign: () => { throw new Error("must not sign"); }, publicKey: () => identity,
  thumbprint: () => "unused", keyIdentity: () => ({ keyId: "weak", publicKey: identity }) };
const input = { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:1", sequence: 0, chainHash: new Uint8Array(32) };
const before = await signAnchor(input, weak, { anchoredAt: 1500 });
if (before.ok || before.error !== "invalid_key_handle") throw new Error("weak key accepted");
const after = await signAnchor(input, testKeyHandle("new-key"), { anchoredAt: 1500 });
if (!after.ok) throw new Error(after.error);
const legacy = "@bounded-authority-protocol/signer/dist/src/api.js";
let closed = false;
try { await import(legacy); } catch (error) {
  closed = (error as { code?: string }).code === "ERR_PACKAGE_PATH_NOT_EXPORTED";
}
if (!closed) throw new Error("deep import is open");
console.log("legacy deep import refused; weak key refused; replacement key signs");
```
<!-- readme-output -->
```text
legacy deep import refused; weak key refused; replacement key signs
```
