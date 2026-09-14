// Test-only fixtures: an in-memory raw Ed25519 key handle (the port of BARA's
// Keys.RawKey — ships in test/, never in the package; the C5 discipline).
import { generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import { thumbprint } from "@bounded-authority-protocol/verifier";
import type { AtomicSigningIdentity, KeyHandle, KeyRole } from "../src/handle.js";

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
  /** Signs with a DIFFERENT key than publicKey() reports — the wrong-key probe. */
  wrongSigningKey?: RawKey;
  /** Counts sign() invocations — the C1 gate must never call sign for a holder. */
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

// RFC 7638 JWK thumbprint (base64url) of a raw Ed25519 public key — the cnf.jkt form.
export const b64Thumbprint = (raw: Uint8Array): string =>
  thumbprint({ kty: "OKP", crv: "Ed25519", x: b64(raw) });
