---
title: "Cheatsheet"
category: Guides
---

# Cheatsheet

| Task | Use | Read |
|---|---|---|
| First issuer → holder → resource integration | `signGrant`, `signReport`, `checkEnvelope` | [Getting started](getting-started.md) |
| Bounded numeric arguments | `signV2Grant` / `signV3Grant` | [Contract majors](contract-majors.md) |
| Browser custody | `ed25519KeyHandle` / `es256KeyHandle` | [WebCrypto](webcrypto.md) |
| Remote custody encodings | Ed25519 raw or ES256 raw r concatenated with s | [Remote custody](remote-custody.md) |
| Local app proof | `signLocalLoopbackReport`, required nonce | [Loopback](local-loopback.md) |
| Chain checkpoint or handover | Suite-specific anchor/transition signer | [Rotation](rotate-keys.md) |
| Handle a refusal | Check `ok`, branch on the closed error code | [Errors](errors.md) |
| Measure safely | Per-call onEvent closure, bounded labels | [Telemetry](telemetry.md) |
| Move from earlier releases | Root imports, valid keys, int-tagged integral values | [Upgrading](upgrading.md) |

Install signer and verifier at the exact versions shown in the [README](../../README.md#install).
Never turn signer success or verifier facts into an authorization decision without host checks.
