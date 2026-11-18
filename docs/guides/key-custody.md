---
title: "The key-handle contract"
category: Guides
---

# The key-handle contract


A handle is any object with these methods (the exported declarations, verbatim; the comments are added):

<!-- readme-sample: types -->
```ts
type KeyRole = "issuer" | "holder";

interface AtomicKeyIdentity {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}

interface AtomicSigningIdentity extends AtomicKeyIdentity {
  readonly role: KeyRole;
}

// Contract-majors 1 and 2, and the local-loopback profile (Ed25519).
interface KeyHandle {
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;                     // 64-byte signature
  publicKey(): Uint8Array | Promise<Uint8Array>;                                    // 32 bytes
  thumbprint(): string | Promise<string>;                                           // RFC 7638, base64url
  keyIdentity?(): AtomicKeyIdentity | Promise<AtomicKeyIdentity>;                   // anchors, key transitions
  signingIdentity?(): AtomicSigningIdentity | Promise<AtomicSigningIdentity>;       // grants
}

// Contract-major 3 (ES256).
interface Es256KeyHandle {
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;                     // 64-byte raw r || s
  publicKey(): Uint8Array | Promise<Uint8Array>;                                    // 65 bytes: 0x04 || x || y
  thumbprint(): string | Promise<string>;                                           // RFC 7638 EC, base64url
  keyIdentity?(): { keyId: string; publicKey: Uint8Array } | Promise<{ keyId: string; publicKey: Uint8Array }>;
  signingIdentity?(): Promise<AtomicSigningIdentity> | AtomicSigningIdentity;
}
```

What the library does with a handle:

- **Which methods it calls.** Every signer calls `sign()`. Report signers read `publicKey()`;
  anchor and key-transition signers read `keyIdentity()`; grant signers read `signingIdentity()`.
  `thumbprint()` is for you: put the holder's thumbprint in the grant's `holderThumbprint`.
- **The issuer-role gate.** A grant signer reads `signingIdentity()` once and fails closed with
  `invalid_key_handle`, before `sign()` is ever called, unless the snapshot's own `role` is
  `"issuer"`. A handle advertising the holder role is refused. The role is a local declaration; the resource independently chooses which issuer keys to trust. `role`, `keyId` and `publicKey` count
  only as the snapshot's own data properties, never inherited ones or getters.
- **Key checks before signing.** An Ed25519 key must be 32 bytes, canonical and not small-order; a
  P-256 key must be the 65-byte uncompressed point on the curve. Anything else is
  `invalid_key_handle`, and `sign()` is not called.
- **The wrong-key guard.** Every signature is verified against the resolved public key before
  assembly, with the verifier's strict checks (`verifyStrict` for Ed25519; for ES256 the library
  first normalizes `s` to low-S, then `es256VerifyStrict` checks it). A handle whose `sign()` used a
  different key (a rotation race, a misconfigured signing service) gets `signing_failed`, never a
  compact that only the verifier would reject.
- **Copies.** `sign()` receives its own copy of the message, and the library keeps private copies of
  the message, the key and the signature, so nothing the handle still holds can change what is
  checked or assembled.
- **Faults.** A handle method or getter that throws, a `null` snapshot or a Proxy-wrapped key is
  `invalid_key_handle`; a `sign()` that throws or returns anything but a 64-byte `Uint8Array` is
  `signing_failed`. An `onEvent` listener that throws is ignored.

An ES256 custodian may return a high `s`: the library replaces it with `n − s`, so every emitted
signature has `0 < s ≤ (n−1)/2` and cannot be re-spelled into a second valid encoding. An `r` or
`s` outside `(0, n)` is `signing_failed`. For a key in a KMS or HSM, see
[Keys in a KMS or HSM](remote-custody.md).
