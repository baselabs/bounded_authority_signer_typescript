---
title: "Keys in a KMS or HSM"
category: Guides
---

# Keys in a KMS or HSM


A handle whose key lives in a KMS or HSM calls the custodian from `sign()`. The library never sees
the private key; it needs only the signature in the form the suite uses and the public key.

- **Ed25519** (contract-majors 1 and 2): an Ed25519 signature is already the 64 bytes the handle
  returns; pass it through.
- **ES256** (contract-major 3): a cloud KMS returns an ECDSA signature as ASN.1 DER
  (`SEQUENCE { INTEGER r, INTEGER s }`, usually 70 to 72 bytes), and the handle returns the 64-byte raw
  `r || s`. Convert it as below. You do not need to normalize `s`: the library replaces a high `s`
  with `n − s` and verifies the result strictly against the handle's public key. A PKCS#11 HSM's
  `CKM_ECDSA` mechanism already returns raw `r || s`.
- **The public key**: AWS KMS `GetPublicKey` returns the DER `SubjectPublicKeyInfo`; Google Cloud
  KMS `getPublicKey` returns the same structure as PEM (its base64 body is the DER). The handle
  reports the 65-byte uncompressed point; WebCrypto converts it.

The call to the KMS is yours: the handle below takes it as a function that signs a message and
returns DER. For an AWS KMS key of spec `ECC_NIST_P256`, hash the message with SHA-256 and call
`Sign` with `MessageType: "DIGEST"` and `SigningAlgorithm: "ECDSA_SHA_256"`; for a Google Cloud KMS
key of algorithm `EC_SIGN_P256_SHA256`, call `asymmetricSign` with `digest: { sha256 }`. Both return
the DER signature. In the sample, that function is a real P-256 key generated in the process, which
returns DER the same way, so the conversion runs on real signatures; in production the private key
stays in the KMS:

<!-- readme-sample: run -->
```ts
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { signV3Grant, signV3Report, type Es256KeyHandle, type KeyRole } from "@bounded-authority-protocol/signer";
import { base64urlEncode, strUtf8, utf8Str, v3, type Tagged } from "@bounded-authority-protocol/verifier";
import { testEs256KeyHandle } from "./key-handle.js";

/** ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` to the 64-byte raw `r || s` of a P-256 signature. */
export function derToRawP256(der: Uint8Array): Uint8Array {
  const malformed = () => new Error("not a DER-encoded P-256 ECDSA signature");
  if (der[0] !== 0x30 || der[1] !== der.length - 2) throw malformed();
  const raw = new Uint8Array(64);
  let at = 2;
  for (const offset of [0, 32]) {
    const length = der[at + 1] ?? 0;
    if (der[at] !== 0x02 || length < 1 || length > 33 || at + 2 + length > der.length) throw malformed();
    let value = der.subarray(at + 2, at + 2 + length);
    if ((value[0]! & 0x80) !== 0 || (value.length > 1 && value[0] === 0 && (value[1]! & 0x80) === 0)) throw malformed();
    if (value.length === 33) {
      if (value[0] !== 0x00) throw malformed();
      value = value.subarray(1); // the sign byte DER adds when the top bit is set
    }
    raw.set(value, offset + 32 - value.length); // DER drops leading zero bytes; restore them
    at += 2 + length;
  }
  if (at !== der.length) throw malformed();
  return raw;
}

/** An ES256 handle over a custodian that signs with ECDSA P-256 SHA-256 and returns DER. */
export async function kmsEs256KeyHandle(
  signDer: (message: Uint8Array) => Promise<Uint8Array>, // your KMS call
  spki: Uint8Array,                                      // the key's DER SubjectPublicKeyInfo
  keyId: string,
  role: KeyRole,
): Promise<Es256KeyHandle> {
  const key = await crypto.subtle.importKey("spki", new Uint8Array(spki), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", key)); // 0x04 || x || y
  const b64 = (bytes: Uint8Array) => utf8Str(base64urlEncode(bytes));
  const jkt = v3.thumbprint({ crv: "P-256", kty: "EC", x: b64(publicKey.subarray(1, 33)), y: b64(publicKey.subarray(33)) });
  return {
    sign: async (message) => derToRawP256(await signDer(message)),
    publicKey: () => publicKey,
    thumbprint: () => jkt,
    keyIdentity: () => ({ keyId, publicKey }),
    signingIdentity: () => ({ role, keyId, publicKey }),
  };
}

// A local cryptographic custodian: a real P-256 key returning DER; this does not call a KMS service.
const custodian = generateKeyPairSync("ec", { namedCurve: "P-256" });
const signDer = async (message: Uint8Array) => new Uint8Array(sign("sha256", message, custodian.privateKey));
const spki = new Uint8Array(custodian.publicKey.export({ type: "spki", format: "der" }));

const issuer = await kmsEs256KeyHandle(signDer, spki, "backup-issuer-kms-1", "issuer");
const agent = testEs256KeyHandle("backup-agent-1");
let verified = 0;
for (let i = 0; i < 16; i++) { // about half of the custodian's signatures have a high s
  const grant = await signV3Grant({
    issuer: "https://backup.example", grantId: `urn:example:grant:snapshot-${i}`,
    audiences: ["https://snapshots.example"],
    issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_229_200,
    holderThumbprint: await agent.thumbprint(),
    operations: [{ name: "create_snapshot", selectors: [{ kind: "equals", path: ["volume"], value: { t: "string", v: strUtf8("data-1") } }] }],
  }, issuer);
  if (!grant.ok) throw new Error(`signV3Grant: ${grant.error}`);
  const request = {
    method: "POST", targetUri: "https://snapshots.example/snapshots", invocationId: randomUUID(), operation: "create_snapshot",
    castArguments: { t: "object", v: new Map<string, Tagged>([["volume", { t: "string", v: strUtf8("data-1") }]]) } satisfies Tagged,
  };
  const envelope = await signV3Report({ grantCompact: grant.value.grant, ...request }, agent, { issuedAt: 1_767_225_660 });
  if (!envelope.ok) throw new Error(`signV3Report: ${envelope.error}`);
  const facts = v3.checkEnvelope(envelope.value.grant, envelope.value.proof, {
    ...request,
    trustedIssuer: { keyId: "backup-issuer-kms-1", publicKey: await issuer.publicKey() },
    issuer: "https://backup.example", audience: "https://snapshots.example",
    evaluationTime: 1_767_225_700, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
  });
  if (facts.ok) verified++;
}
console.log(`${verified} of 16 envelopes verify under the custodian's key`);
```

<!-- readme-output -->
```text
16 of 16 envelopes verify under the custodian's key
```

Test such a handle the way [Test your integration](test-your-integration.md) describes: a `sign()`
that rejects, and one that signs with another key, must both give `signing_failed`.
