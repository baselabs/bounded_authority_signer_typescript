---
title: "FAQ"
category: Guides
---

# FAQ

## Does signing mean the operation is allowed?

No. Signing produces bytes and checks the returned signature against the handle's public key.
Resource verification returns facts; host policy, revocation and replay reservation decide execution.

## Can I reuse a proof?

The signer stores no replay state. A resource may reserve a proof or invocation once. For a retry,
follow that host's protocol; do not infer safety from another successful cryptographic verification.

## Why did a valid-looking key fail?

Check suite and width, atomic identity and issuer role. A WebCrypto factory also requires a real,
matching non-extractable pair. See [errors](errors.md) and [WebCrypto](webcrypto.md).

## Why does 30.0 fail as a bound?

JavaScript has already made it integral. Canonical JSON would erase its float tag. Use an int-tagged
30. Fractional values retain the float tag. See the [executed upgrade check](errors.md#float-tagged-integral-selector-values).

## Are a browser and a worker different authorization models?

No. Both are host environments. A worker can hold a CryptoKey or a handle; neither substitutes for
resource-side trust or policy. See [recipes](recipes.md).

## Does WebKit CI certify Safari?

No. It exercises the pinned Linux WebKit build. Browser support must be validated on the engines
and deployment versions your host supports.
