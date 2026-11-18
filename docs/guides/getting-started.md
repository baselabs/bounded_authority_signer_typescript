---
title: "Quickstart"
category: Guides
---

# Quickstart


An issuer grants an agent read access to one repository; the agent proves one request; the
resource server verifies it. You need Node.js 22 or later. In an empty directory, create an ES
module project (the examples use top-level `await`), install both packages, and install
[tsx](https://www.npmjs.com/package/tsx) to run TypeScript:

<!-- readme-sample: setup -->
```bash
npm init -y && npm pkg set type=module
npm install @bounded-authority-protocol/signer@2.0.0 @bounded-authority-protocol/verifier@2.0.0
npm install --save-dev tsx
```

First, a key handle over in-process keys, for trying the library (in production, `sign()` calls
your KMS, HSM or WebCrypto key instead). Save it as `key-handle.ts`:

<!-- readme-sample: file key-handle.ts -->
```ts
import { generateKeyPairSync, sign } from "node:crypto";
import { jwkFromPublicKey, thumbprint, v3 } from "@bounded-authority-protocol/verifier";
import type { Es256KeyHandle, KeyHandle, KeyRole } from "@bounded-authority-protocol/signer";

const fromBase64url = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "base64url"));

/** An Ed25519 handle over a fresh in-process key (contract-majors 1 and 2). */
export function testKeyHandle(keyId: string, role: KeyRole = "holder"): KeyHandle {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = fromBase64url(publicKey.export({ format: "jwk" }).x!);
  return {
    sign: (message) => new Uint8Array(sign(null, message, privateKey)),
    publicKey: () => raw,
    thumbprint: () => thumbprint(jwkFromPublicKey(raw)),
    keyIdentity: () => ({ keyId, publicKey: raw }),
    signingIdentity: () => ({ role, keyId, publicKey: raw }),
  };
}

/** An ES256 handle over a fresh in-process P-256 key (contract-major 3). */
export function testEs256KeyHandle(keyId: string, role: KeyRole = "holder"): Es256KeyHandle {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const raw = new Uint8Array([0x04, ...fromBase64url(x), ...fromBase64url(y)]);
  return {
    sign: (message) => new Uint8Array(sign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" })),
    publicKey: () => raw,
    thumbprint: () => v3.thumbprint({ crv: "P-256", kty: "EC", x, y }),
    keyIdentity: () => ({ keyId, publicKey: raw }),
    signingIdentity: () => ({ role, keyId, publicKey: raw }),
  };
}
```

Then `quickstart.ts`, and run it with `npx tsx quickstart.ts`:

<!-- readme-sample: run -->
```ts
import { signGrant, signReport } from "@bounded-authority-protocol/signer";
import { checkEnvelope, strUtf8, type Tagged } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const issuer = testKeyHandle("issuer-key-1", "issuer"); // the authorization server's key
const agent = testKeyHandle("agent-key-1");             // the holder: the agent's own key

// 1. The issuer grants the agent one operation on one repository, for two hours.
const grant = await signGrant({
  issuer: "https://issuer.example",
  grantId: "urn:example:grant:1",
  audiences: ["https://code.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_232_800,
  holderThumbprint: await agent.thumbprint(),
  operations: [{
    name: "read_file",
    selectors: [{ kind: "equals", path: ["repository"], value: { t: "string", v: strUtf8("example/website") } }],
  }],
}, issuer);
if (!grant.ok) throw new Error(`signGrant: ${grant.error}`);

// 2. The agent proves one request under that grant.
const args: Tagged = { t: "object", v: new Map<string, Tagged>([
  ["repository", { t: "string", v: strUtf8("example/website") }],
  ["path", { t: "string", v: strUtf8("README.md") }],
]) };
const request = {
  method: "GET",
  targetUri: "https://code.example/files",
  invocationId: "0f8d5a5e-7c3b-4e7a-9a51-2f4c1d6b8e90", // a lowercase RFC 4122 UUID
  operation: "read_file",
  castArguments: args,
};
const envelope = await signReport({ grantCompact: grant.value.grant, ...request }, agent, { issuedAt: 1_767_225_660 });
if (!envelope.ok) throw new Error(`signReport: ${envelope.error}`);

// 3. The resource server verifies the pair with the verifier package and gets facts, not a decision.
const facts = checkEnvelope(envelope.value.grant, envelope.value.proof, {
  ...request,                       // the request the server actually received
  trustedIssuer: { keyId: "issuer-key-1", publicKey: await issuer.publicKey() }, // a key the server already trusts
  issuer: "https://issuer.example", // the issuer the grant must name
  audience: "https://code.example", // this server: one of the grant's audiences
  evaluationTime: 1_767_225_700,    // "now", in Unix seconds: the verifier reads no clock
  clockSkew: 60,                    // seconds of tolerance between the parties' clocks
  proofMaxAge: 300,                 // seconds a proof stays acceptable after its issuedAt
  nonce: { kind: "not_required" },  // this server issues no nonces
});
if (!facts.ok) throw new Error("the envelope did not verify");
console.log(`verified: ${facts.value.operation} under ${facts.value.grantId}`);
```

Output:

<!-- readme-output -->
```text
verified: read_file under urn:example:grant:1
```

Every signer returns `{ ok: true, value }` or `{ ok: false, error }`; check `ok` before reading
`value`. Change the `repository` argument to another value and `checkEnvelope` returns
`{ ok: false }`: the proof still signs, but the grant's `equals` selector does not match.


## Guided notebooks

See the [Deno notebook launch instructions](../notebooks/README.md) and these complete journeys:

- [Grant and proof](../notebooks/grant-and-proof.ipynb)
- [Bounded selectors es256](../notebooks/bounded-selectors-es256.ipynb)
- [Key custody](../notebooks/key-custody.ipynb)
- [Local loopback](../notebooks/local-loopback.ipynb)
- [Anchors and transitions](../notebooks/anchors-and-transitions.ipynb)
