// Test-only fixtures include an in-memory raw Ed25519 handle mirroring BARA's
// Keys.RawKey. It ships in test/ only, following the C5 discipline, alongside
// the ES256 (P-256) fixtures for the v3 suite: an in-memory EC key whose
// thumbprint is computed INDEPENDENTLY of src/ (literal RFC 7638 preimage +
// node:crypto hash) so the library's JCS-based spelling is cross-checked, and
// a handle that signs through crypto.sign's ieee-p1363 (raw r||s) encoding.
import { createHash, generateKeyPairSync, sign as edSign, sign as ecSign, type KeyObject } from "node:crypto";
import { thumbprint } from "@bounded-authority-protocol/verifier";
import type { AtomicSigningIdentity, KeyHandle, KeyRole } from "../src/handle.js";
import type { Es256KeyHandle } from "../src/apiV3.js";

export interface RawKey {
  publicKey: Uint8Array;
  privateKey: KeyObject;
  thumbprint: string;
}

export function rawKey(): RawKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const pub = new Uint8Array(Buffer.from(jwk.x, "base64url"));
  return { publicKey: pub, privateKey, thumbprint: b64Thumbprint(pub) };
}

export interface HandleOpts {
  keyId: string;
  role?: KeyRole;
  withKeyIdentity?: boolean;
  /** Probe the wrong-key guard by signing with a key other than the one publicKey() reports. */
  wrongSigningKey?: RawKey;
  /** Count sign() invocations to confirm the C1 gate refuses a holder before signing. */
  signCalls?: { count: number };
}

export function handleFor(key: RawKey, opts: HandleOpts): KeyHandle {
  const signingKey = opts.wrongSigningKey ?? key;
  return {
    sign: (message: Uint8Array) => {
      if (opts.signCalls !== undefined) opts.signCalls.count += 1;
      return new Uint8Array(edSign(null, Buffer.from(message), signingKey.privateKey));
    },
    publicKey: () => key.publicKey,
    thumbprint: () => key.thumbprint,
    ...(opts.withKeyIdentity === false ? {} : {
      keyIdentity: () => ({ keyId: opts.keyId, publicKey: key.publicKey }),
    }),
    ...(opts.role === undefined ? {} : {
      signingIdentity: (): AtomicSigningIdentity => ({ role: opts.role!, keyId: opts.keyId, publicKey: key.publicKey }),
    }),
  };
}

// Deterministic cast arguments: {"amount": 5000}
export type AmountArgs = { t: "object"; v: Map<string, { t: "int"; v: number }> };

export const amountArgs = (): AmountArgs => ({
  t: "object",
  v: new Map([["amount", { t: "int", v: 5000 }]]),
});

export const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64url");

// The cnf.jkt form is the RFC 7638 JWK thumbprint of a raw Ed25519 public key, in base64url.
export const b64Thumbprint = (raw: Uint8Array): string =>
  thumbprint({ kty: "OKP", crv: "Ed25519", x: b64(raw) });

// ES256 (P-256) fixtures for the v3 suite.

export interface EcRawKey {
  publicKey: Uint8Array;  // 65-byte uncompressed SEC1: 0x04 || x || y
  privateKey: KeyObject;
  thumbprint: string;     // RFC 7638 EC thumbprint, base64url
  jwk: { crv: "P-256"; kty: "EC"; x: string; y: string };
}

// Independent RFC 7638 EC thumbprint: SHA-256 over the LITERAL lexicographic
// JSON preimage. This path uses no src/ code, so agreement with the library's
// JCS-built preimage is a cross-check, not a tautology.
const ecThumbprintIndependent = (jwk: { x: string; y: string }): string =>
  createHash("sha256")
    .update(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`, "utf8")
    .digest("base64url");

export function ecRawKey(): EcRawKey {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string; y: string };
  const pub = new Uint8Array(65);
  pub[0] = 0x04;
  pub.set(Buffer.from(jwk.x, "base64url"), 1);
  pub.set(Buffer.from(jwk.y, "base64url"), 33);
  return {
    publicKey: pub,
    privateKey,
    thumbprint: ecThumbprintIndependent(jwk),
    jwk: { crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y },
  };
}

export interface EcHandleOpts {
  keyId: string;
  role?: KeyRole;
  withKeyIdentity?: boolean;
  /** Probe the wrong-key guard by signing with a key other than the one publicKey() reports. */
  wrongSigningKey?: EcRawKey;
  /** Count sign() invocations to confirm the C1 gate refuses a holder before signing. */
  signCalls?: { count: number };
  /** Records each raw (pre-normalization) signature the handle returned. */
  rawSignatures?: Uint8Array[];
}

export function ecHandleFor(key: EcRawKey, opts: EcHandleOpts): Es256KeyHandle {
  const signingKey = opts.wrongSigningKey ?? key;
  return {
    sign: (message: Uint8Array) => {
      if (opts.signCalls !== undefined) opts.signCalls.count += 1;
      const sig = new Uint8Array(ecSign("SHA256", Buffer.from(message), { key: signingKey.privateKey, dsaEncoding: "ieee-p1363" }));
      opts.rawSignatures?.push(sig);
      return sig;
    },
    publicKey: () => key.publicKey,
    thumbprint: () => key.thumbprint,
    ...(opts.withKeyIdentity === false ? {} : {
      keyIdentity: () => ({ keyId: opts.keyId, publicKey: key.publicKey }),
    }),
    ...(opts.role === undefined ? {} : {
      signingIdentity: (): AtomicSigningIdentity => ({ role: opts.role!, keyId: opts.keyId, publicKey: key.publicKey }),
    }),
  };
}
