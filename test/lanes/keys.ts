// Test-local caller-owned key handles for the runtime lanes (Node, Deno, Bun and real browsers). The
// keys are generated per run by @noble/curves (a dev dependency, pure JS, the same bytes on every
// engine), and each handle signs through the existing KeyHandle / Es256KeyHandle contract. This file
// is test code: the package never generates, holds or signs with a private key, and src/ is linted to
// keep noble and WebCrypto out of it.
//
// The ES256 handle signs with noble's lowS: false, so about half of its raw signatures are high-S:
// the library's normalization and strict post-sign check are exercised on every engine.
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { base64urlEncode, thumbprint, utf8Str, v3 } from "@bounded-authority-protocol/verifier";
import type { Es256KeyHandle, KeyHandle, KeyRole } from "../../src/index.js";

const b64 = (bytes: Uint8Array): string => utf8Str(base64urlEncode(bytes));

export interface EdKey { readonly publicKey: Uint8Array; readonly thumbprint: string; sign(message: Uint8Array): Uint8Array }
export interface EcKey { readonly publicKey: Uint8Array; readonly thumbprint: string; sign(message: Uint8Array): Uint8Array }

export function edKey(): EdKey {
  const { secretKey, publicKey } = ed25519.keygen();
  return { publicKey, thumbprint: thumbprint({ kty: "OKP", crv: "Ed25519", x: b64(publicKey) }), sign: (m) => ed25519.sign(m, secretKey) };
}

export function ecKey(): EcKey {
  const { secretKey, publicKey } = p256.keygen();
  const raw = p256.Point.fromBytes(publicKey).toBytes(false); // 65-byte uncompressed SEC1
  return {
    publicKey: raw,
    thumbprint: v3.thumbprint({ crv: "P-256", kty: "EC", x: b64(raw.subarray(1, 33)), y: b64(raw.subarray(33)) }),
    sign: (m) => p256.sign(m, secretKey, { lowS: false, prehash: true, format: "compact" }),
  };
}

export interface HandleOpts { readonly keyId: string; readonly role?: KeyRole; readonly signWith?: { sign(message: Uint8Array): Uint8Array }; readonly raw?: Uint8Array[] }

export function edHandle(key: EdKey, opts: HandleOpts): KeyHandle {
  const signer = opts.signWith ?? key;
  return {
    sign: (m) => signer.sign(m),
    publicKey: () => key.publicKey,
    thumbprint: () => key.thumbprint,
    keyIdentity: () => ({ keyId: opts.keyId, publicKey: key.publicKey }),
    ...(opts.role === undefined ? {} : { signingIdentity: () => ({ role: opts.role!, keyId: opts.keyId, publicKey: key.publicKey }) }),
  };
}

export function ecHandle(key: EcKey, opts: HandleOpts): Es256KeyHandle {
  const signer = opts.signWith ?? key;
  return {
    sign: (m) => {
      const signature = signer.sign(m);
      opts.raw?.push(signature);
      return signature;
    },
    publicKey: () => key.publicKey,
    thumbprint: () => key.thumbprint,
    keyIdentity: () => ({ keyId: opts.keyId, publicKey: key.publicKey }),
    ...(opts.role === undefined ? {} : { signingIdentity: () => ({ role: opts.role!, keyId: opts.keyId, publicKey: key.publicKey }) }),
  };
}
