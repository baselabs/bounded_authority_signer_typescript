---
title: "Browsers, Deno, Bun and workers"
category: Guides
---

# Browsers, Deno, Bun and workers


The package is ESM-only, has no side effects on import (`"sideEffects": false`), and uses no
Node API: no `node:*` module, no `Buffer`, no `process`. Every cryptographic operation it
performs itself (the post-sign verify, SHA-256) comes from the verifier package, which picks
its own backend through its `"imports"` conditions, so a browser bundle, Deno and Bun get the
verifier's pure-JavaScript portable backend and Node.js keeps `node:crypto`:

| Runtime | Verifier `BACKEND_ID` |
|---|---|
| Node.js (default conditions) | `"node"` |
| Node.js with `--conditions=bap-portable` | `"portable"` |
| Deno, Bun | `"portable"` |
| Browsers and bundlers targeting them, workers | `"portable"` |

<!-- readme-sample: run -->
```ts
import { BACKEND_ID } from "@bounded-authority-protocol/verifier";

// "node" or "portable": which verifier backend this build resolved. Signing behaves the same in both.
if (BACKEND_ID !== "node" && BACKEND_ID !== "portable") throw new Error("unknown backend");
console.log("verifier backend recognized");
```

<!-- readme-output -->
```text
verifier backend recognized
```

The signer never touches private-key bytes: signing is always a handle's `sign()`, wherever and
however that handle is implemented. The only WebCrypto it uses is in the
[WebCrypto key handles](webcrypto.md): `crypto.subtle.sign` with your
non-extractable `CryptoKey`, and `exportKey("raw")` of the public key.

In Deno, Bun and browsers, build handles with the [WebCrypto key handles](webcrypto.md). The
`node:crypto` handle in the getting-started guide is a Node.js pattern: Deno's Node
compatibility layer (checked with Deno 2.5.6) returns DER from `sign()` for a P-256 key whatever
`dsaEncoding` asks for, and the signer refuses a DER signature.

**In-page verification is display-only, never a trust decision.** If a page signs and then
verifies an envelope (as the playground does), that result is for showing to a person. It
must not authorize anything, feed a trust decision, or be sent anywhere as evidence of
authority: the page's own scripts, browser extensions and injected code share its origin and
can change both the inputs and the answer. The trusted decision stays with the host runtime
that holds the trusted keys.

The package works under a strict Content Security Policy (`default-src 'none'; script-src
'self'; connect-src 'self'`, no `'unsafe-eval'`): it uses no `eval`, no `Function` constructor
and no dynamic `import()`. The default `proofId` comes from `crypto.randomUUID()`, which
browsers provide only in a secure context (HTTPS or `localhost`). On a plain-HTTP page, pass
`proofId` explicitly; without it the report signers return the closed `producer_error`.

Run `pnpm size` for measured bundle sizes and enforced limits.
