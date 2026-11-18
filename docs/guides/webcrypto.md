---
title: "WebCrypto key handles"
category: Guides
---

# WebCrypto key handles


Two factories build the [key handles](key-custody.md) from a WebCrypto key pair whose private key is
**non-extractable**, so a page (or Deno, Bun or Node) signs with a key it cannot export.
`ed25519KeyHandle(pair, opts?)` returns a `KeyHandle`, `es256KeyHandle(pair, opts?)` an
`Es256KeyHandle`. `opts.keyId` (a non-empty string) adds `keyIdentity()` and `signingIdentity()`;
`opts.role` is `"holder"` (the default) or `"issuer"`. Each resolves a `SignerResult`: never a throw
or a rejection, and on any failure the value-free `invalid_key_handle`.

<!-- readme-sample: run-dom -->
```ts
import { ed25519KeyHandle, es256KeyHandle, signGrant, signV3Anchor } from "@bounded-authority-protocol/signer";

// WebKit for Linux can transiently refuse key generation; retry only OperationError.
async function generatePair(algorithm: Algorithm | EcKeyGenParams, extractable = false): Promise<CryptoKeyPair> {
  for (let attempt = 0; attempt < 3; attempt++) {
    try { return await crypto.subtle.generateKey(algorithm, extractable, ["sign", "verify"]) as CryptoKeyPair; }
    catch (error) { if ((error as { name?: string }).name !== "OperationError" || attempt === 2) throw error; }
  }
  throw new Error("key generation failed");
}

// You create the pair and own its lifetime; the library never generates, imports or exports a private key.
const issuerPair = await generatePair({ name: "Ed25519" });
const issuer = await ed25519KeyHandle(issuerPair, { keyId: "issuer-key-1", role: "issuer" });
if (!issuer.ok) throw new Error(issuer.error);

const agentPair = await generatePair({ name: "Ed25519" });
const agent = await ed25519KeyHandle(agentPair); // role "holder"
if (!agent.ok) throw new Error(agent.error);

const grant = await signGrant({
  issuer: "https://issuer.example", grantId: "urn:example:grant:calendar",
  audiences: ["https://calendar.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_232_800,
  holderThumbprint: await agent.value.thumbprint(),
  operations: [{ name: "create_event", selectors: [{ kind: "all" }] }],
}, issuer.value);

// Contract-major 3 (ES256): the same with an ECDSA P-256 pair.
const ledgerPair = await generatePair({ name: "ECDSA", namedCurve: "P-256" });
const ledger = await es256KeyHandle(ledgerPair, { keyId: "ledger-key-1" });
if (!ledger.ok) throw new Error(ledger.error);
const anchor = await signV3Anchor(
  { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:ledger", sequence: 0, chainHash: new Uint8Array(32) },
  ledger.value,
);

// An extractable private key is refused.
const exportable = await generatePair({ name: "Ed25519" }, true);
const refused = await ed25519KeyHandle(exportable);
console.log(`grant: ${grant.ok}; anchor: ${anchor.ok}; extractable pair: ${refused.ok ? "accepted" : refused.error}`);
```

<!-- readme-output -->
```text
grant: true; anchor: true; extractable pair: invalid_key_handle
```

The parameter type is structural: a DOM `CryptoKeyPair` and Node's `webcrypto.CryptoKeyPair` pass
without a cast. The sample above typechecks with the DOM library. One exception comes from the Node
types: `@types/node` (26.6.6) types `webcrypto.subtle.generateKey({ name: "Ed25519" }, ...)` as
`Promise<CryptoKey>`, so cast its result:

<!-- readme-sample: run -->
```ts
import { webcrypto } from "node:crypto";
import { ed25519KeyHandle } from "@bounded-authority-protocol/signer";

const pair = (await webcrypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as unknown as webcrypto.CryptoKeyPair;
const made = await ed25519KeyHandle(pair);
console.log(`handle: ${made.ok}`);
```

<!-- readme-output -->
```text
handle: true
```

**What the factory checks**, in this order. Any failure is `invalid_key_handle`, with no detail:

1. a secure context with `crypto.subtle` (on a plain-HTTP page there is none, and nothing you
   passed is read);
2. the options (`keyId` a non-empty string, `role` `"holder"` or `"issuer"`), read from the
   options object's own data properties only: an inherited `role` or `keyId`, including one on a
   polluted `Object.prototype`, is ignored. The pair's two keys are read the same way;
3. both keys are real `CryptoKey`s: every fact is read through the `CryptoKey.prototype`
   getters, never through `key.extractable`, and each key must be structured-cloneable (a
   `Proxy` never is), so a shadowed property, a plain object or a `Proxy` is refused. The clones
   run after the checks of steps 4 to 6, and the public key's after its raw export at step 7:
   WebKit on Linux terminates the page when it clones a raw-imported P-256 key with a bad point
   prefix, while that key's export fails cleanly. On Deno, where a `Proxy` can reach a key's
   internal slots, a `Proxy` that passes a private key off as the public one makes that export
   return private bytes; the factory zeroes its copy and the clone refuses the `Proxy`;
4. a private and a public key;
5. the private key is non-extractable (always; there is no option to allow an extractable key);
6. `Ed25519` for both keys, or `ECDSA` on `P-256` for both;
7. the public key's raw export: 32 bytes, canonical, not small-order and torsion-free; or the
   65-byte uncompressed point on the curve;
8. one probe signature with the private key over a fixed message containing a zero byte (so it
   is never a JWS signing input), verified strictly against that export. A mismatched pair, or a
   relabeled algorithm (an X25519 pair renamed Ed25519), fails here.

Everything the factory and the handle take from the environment is captured when the module loads:
`crypto.subtle`, `SubtleCrypto.prototype.sign` and `exportKey`, the `CryptoKey` getters,
`structuredClone` and `Reflect.apply`. A script that patches them later changes neither the checks
nor what an existing handle calls.

**The handle signs only JWS signing inputs.** Its `sign()` accepts only bytes shaped
`base64url "." base64url` and rejects anything else; within the signers that is `signing_failed`.
The message must be a `Uint8Array` from the same realm as the library: a typed array made in another
iframe or `vm` context fails the `instanceof Uint8Array` test and is rejected. The signers always pass
their own copy, so this matters only if you call `handle.sign()` yourself.
The ES256 handle returns WebCrypto's raw `r || s` unchanged (high-`s` about half the time), and the
shared v3 path normalizes it to low-`s` and verifies it strictly, exactly as for your own handles.
The handle is frozen, its only properties are its methods, and the `CryptoKey` lives only in its
closure; `JSON.stringify(handle)` is `{}`.

**Threat model.** Read this before you keep a signing key in a page.

- **Non-extractable stops export, not use.** Any script running in the origin that reaches the
  handle or the `CryptoKey` (or reads the key back from IndexedDB) can sign silently, with no
  prompt: an XSS payload, a compromised dependency, an extension with page access. A signature
  from these handles proves that code in that origin used the key, not that a person approved
  the bytes. Approval (a user gesture, a confirmation screen, rate limits) is yours to add.
  Containment belongs to the protocol and the host runtime: narrow grants, short `exp`, exact
  operations and audiences, and the runtime's replay and revocation.
- **One key per purpose.** The handle signs any JWS signing input, so a pair used here must not
  sign anything else (another protocol, another JWS consumer).
- **Non-extractable is a browser property only.** On Node and Bun, any code in the process can
  export a non-extractable private key with `KeyObject.from(key).export()` (Node 24 prints a
  deprecation warning and still exports). Deno refuses. On a server, prefer a handle that reaches
  a KMS or HSM.
- **The extractable refusal guards against accidents**, not against the key's holder. It
  stops an exportable key from being paired with a handle meant for a non-exportable one. The
  getter reads and the structured-clone check refuse every disguise tested (a shadowed property, a
  plain object, a `Proxy`, including one that lies to Deno's getters), but whoever owns the key
  already controls it (on Node and Bun they can export it anyway), so the refusal is never a
  security boundary against that caller.
- **Persistence is yours.** The library stores nothing. A `CryptoKey` you save to IndexedDB stays
  non-extractable, and lives in the browser profile on disk; clearing site data, eviction and
  private browsing lose it. Rotating the pair means building a new handle (the public key is a
  snapshot).
- **Not hardware-backed.** WebCrypto keys are browser-managed software keys with no attestation.
- **Retry key generation on WebKit for Linux.** WebKit 27.2 on Linux rejects about 1% of
  Ed25519 `generateKey` calls with an `OperationError` (measured: 19 of 2000; P-256: 0 of 2000).
  Generating the pair is your code, so retry that error a few times.
- **Other realms.** A key generated in a same-origin iframe, or generated in a dedicated worker
  and posted to the page, is accepted (the getters brand-check; there is no `instanceof` test); the
  browser lanes test both. Deno cannot hand a `CryptoKey` across realms: its structured clone of a
  `CryptoKey` is not a usable key, so generate keys where you sign.
- **Harden the page that holds a key:** the strict Content Security Policy described in
  [Browsers, Deno, Bun and workers](runtimes.md), Trusted Types, Subresource
  Integrity, a minimal dependency set, and a dedicated origin for key use. In-page verification
  stays display-only.

Ed25519 in WebCrypto needs Chrome 137, Firefox 129 or Safari 17 or later; ECDSA P-256 is
everywhere. CI exercises the factories in Chromium, Firefox and WebKit on Linux, Node, Deno and
Bun. Linux WebKit is evidence for that WebKit build only, not for Safari's WebCrypto.
