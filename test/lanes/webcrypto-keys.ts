// Test-local WebCrypto keys for the key-handle tests, in every lane (Node 22 and 24, Deno, Bun and real
// browsers). Every key is REAL: generated, imported or exported by the engine under test through its own
// crypto.subtle. Nothing is mocked. This file is test code: the package itself never generates, imports
// or exports a private key (src/webcrypto.ts only exports the public key in raw form and signs).
//
// The structural types keep this file engine-neutral: it typechecks under the Node types (tsconfig.json)
// and under the DOM library (browser/tsconfig.json) alike.
import type { WebCryptoKeyPairLike } from "../../src/index.js";

export interface TestSubtle {
  generateKey(algorithm: object, extractable: boolean, usages: string[]): Promise<unknown>;
  importKey(format: "raw", data: Uint8Array, algorithm: object, extractable: boolean, usages: string[]): Promise<unknown>;
  exportKey(format: "raw", key: unknown): Promise<ArrayBuffer>;
  sign(algorithm: object, key: unknown, data: Uint8Array): Promise<ArrayBuffer>;
}

export const subtle = (): TestSubtle => (globalThis as unknown as { crypto: { subtle: TestSubtle } }).crypto.subtle;

export const ED25519 = { name: "Ed25519" } as const;
export const X25519 = { name: "X25519" } as const;
export const P256 = { name: "ECDSA", namedCurve: "P-256" } as const;
export const P384 = { name: "ECDSA", namedCurve: "P-384" } as const;
export const ES256_SIGN = { name: "ECDSA", hash: "SHA-256" } as const;

export type Pair = WebCryptoKeyPairLike;

export async function generate(algorithm: object, extractable: boolean, usages: string[] = ["sign", "verify"]): Promise<Pair> {
  return (await subtle().generateKey(algorithm, extractable, usages)) as Pair;
}

export const edPair = (extractable = false): Promise<Pair> => generate(ED25519, extractable);
export const ecPair = (extractable = false): Promise<Pair> => generate(P256, extractable);

export async function rawPublicKey(pair: Pair): Promise<Uint8Array> {
  return new Uint8Array(await subtle().exportKey("raw", pair.publicKey));
}

/** Import raw public-key bytes as a public CryptoKey; undefined when the engine refuses the bytes. */
export async function importPublic(raw: Uint8Array, algorithm: object): Promise<Pair["publicKey"] | undefined> {
  try {
    return (await subtle().importKey("raw", raw, algorithm, true, ["verify"])) as Pair["publicKey"];
  } catch {
    return undefined;
  }
}

export const hex = (h: string): Uint8Array => new Uint8Array((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));

// Weak Ed25519 public keys (literal vectors; every engine tested so far imports them as public CryptoKeys).
export const WEAK_ED25519: Readonly<Record<string, string>> = {
  identity: "0100000000000000000000000000000000000000000000000000000000000000",
  "small-order (order 8)": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "non-canonical (y = p)": "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "torsioned (honest point plus a small-order point)": "b0bf871d60747d0844233d10a302f324ecce2029f019fb2bf18c991239ee932f",
};

// The P-256 field prime, for building x >= p mutations.
export const P256_PRIME = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

/** Mutations of a real 65-byte P-256 raw export that the factory must refuse. */
export function p256Mutations(raw: Uint8Array): Record<string, Uint8Array> {
  const offCurve = new Uint8Array(raw);
  offCurve[64] = (offCurve[64] ?? 0) ^ 1;
  const xIsP = new Uint8Array(raw);
  let p = P256_PRIME;
  for (let i = 32; i >= 1; i--) {
    xIsP[i] = Number(p & 0xffn);
    p >>= 8n;
  }
  const xAllOnes = new Uint8Array(raw);
  xAllOnes.fill(0xff, 1, 33);
  const prefix = new Uint8Array(raw);
  prefix[0] = 0x05;
  const compressed = new Uint8Array(33);
  compressed[0] = 2 + ((raw[64] ?? 0) & 1);
  compressed.set(raw.subarray(1, 33), 1);
  return {
    "off-curve (y flipped)": offCurve,
    "x = p": xIsP,
    "x = 2^256 - 1 (>= p)": xAllOnes,
    "prefix 0x05": prefix,
    "64 bytes (truncated)": raw.slice(0, 64),
    "33-byte compressed form": compressed,
  };
}

/** Mutations of a real 32-byte Ed25519 raw export that the factory must refuse. */
export function ed25519Mutations(raw: Uint8Array): Record<string, Uint8Array> {
  const out: Record<string, Uint8Array> = {};
  for (const [name, h] of Object.entries(WEAK_ED25519)) out[name] = hex(h);
  out["31 bytes"] = raw.slice(0, 31);
  const longer = new Uint8Array(33);
  longer.set(raw);
  out["33 bytes"] = longer;
  return out;
}
