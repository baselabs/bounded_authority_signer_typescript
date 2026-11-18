---
title: "Contract-major 3: ES256"
category: Guides
---

# Contract-major 3: ES256


The v3 signers sign the `BAP3-ES256-SHA256` suite: `alg: "ES256"` headers, payload `v: 3`, the
`BAP3-*` separators, the EC proof key `{"crv":"P-256","kty":"EC","x":…,"y":…}` with its RFC 7638
thumbprint as `cnf.jkt`, the five selector kinds, 65-byte uncompressed public keys and 64-byte raw
`r || s` signatures, low-S normalized (see [the key-handle contract](key-custody.md)). The
v3 signing inputs are built in this package; the v1 and v2 ones come from the verifier's producers.
Here a deploy bot may scale one service up to 10 replicas:

<!-- readme-sample: run -->
```ts
import { signV3Grant, signV3Report } from "@bounded-authority-protocol/signer";
import { strUtf8, v3, type Tagged } from "@bounded-authority-protocol/verifier";
import { testEs256KeyHandle } from "./key-handle.js";

const platform = testEs256KeyHandle("platform-issuer-1", "issuer");
const deployBot = testEs256KeyHandle("deploy-bot-1");

const grant = await signV3Grant({
  issuer: "https://platform.example", grantId: "urn:example:grant:scale-web",
  audiences: ["https://deploy.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_227_400,
  holderThumbprint: await deployBot.thumbprint(),
  operations: [{ name: "scale_service", selectors: [
    { kind: "equals", path: ["service"], value: { t: "string", v: strUtf8("web") } },
    { kind: "lte", path: ["replicas"], value: { t: "int", v: 10 } },
  ] }],
}, platform);
if (!grant.ok) throw new Error(`signV3Grant: ${grant.error}`);

const request = {
  method: "POST", targetUri: "https://deploy.example/scale",
  invocationId: "6a1f0d3c-2b4e-4f5a-8c6d-7e8f9a0b1c2d", operation: "scale_service",
  castArguments: { t: "object", v: new Map<string, Tagged>([
    ["service", { t: "string", v: strUtf8("web") }],
    ["replicas", { t: "int", v: 4 }],
  ]) } satisfies Tagged,
};
const envelope = await signV3Report({ grantCompact: grant.value.grant, ...request }, deployBot, { issuedAt: 1_767_225_660 });
if (!envelope.ok) throw new Error(`signV3Report: ${envelope.error}`);

const facts = v3.checkEnvelope(envelope.value.grant, envelope.value.proof, {
  ...request,
  trustedIssuer: { keyId: "platform-issuer-1", publicKey: await platform.publicKey() },
  issuer: "https://platform.example", audience: "https://deploy.example",
  evaluationTime: 1_767_225_700, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
});
console.log(`v3 envelope verifies: ${facts.ok}`);
```

<!-- readme-output -->
```text
v3 envelope verifies: true
```

`signV3Anchor` and `signV3KeyTransition` work like their [major-1 counterparts](rotate-keys.md), with
an `Es256KeyHandle` and a 65-byte `nextPublicKey`:

<!-- readme-sample: run -->
```ts
import { signV3Anchor, signV3KeyTransition } from "@bounded-authority-protocol/signer";
import { base64urlDecode, strUtf8, v3 } from "@bounded-authority-protocol/verifier";
import { testEs256KeyHandle } from "./key-handle.js";

const current = testEs256KeyHandle("ledger-key-1");
const next = testEs256KeyHandle("ledger-key-2");
const fingerprint = async (handle: typeof current) => base64urlDecode(strUtf8(await handle.thumbprint()));
const chainHash = new Uint8Array(32); // the chain's hash at this sequence (all zero at genesis)

const anchor = await signV3Anchor(
  { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:ledger", sequence: 0, chainHash },
  current, { anchoredAt: 1_767_225_600 },
);
const transition = await signV3KeyTransition({
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:ledger",
  effectiveAt: 1_767_312_000, nextKeyId: "ledger-key-2", nextPublicKey: await next.publicKey(),
}, current);
if (!anchor.ok || !transition.ok) throw new Error("signing failed");

const currentKey = { keyId: "ledger-key-1", publicKey: await current.publicKey(), validFrom: 0, validBefore: null };
const nextKey = { keyId: "ledger-key-2", publicKey: await next.publicKey(), validFrom: 1_767_312_000, validBefore: null };
const anchorFacts = v3.verifyHistoricalAnchor(anchor.value.anchor, currentKey, {
  anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:ledger", keyId: "ledger-key-1",
  sequence: 0, anchoredAt: 1_767_225_600, chainHash, keyFingerprint: await fingerprint(current),
});
const transitionFacts = v3.verifyKeyTransition(transition.value.keyTransition, currentKey, nextKey, {
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:ledger", effectiveAt: 1_767_312_000,
  currentKeyId: "ledger-key-1", nextKeyId: "ledger-key-2",
  currentKeyFingerprint: await fingerprint(current), nextKeyFingerprint: await fingerprint(next),
});
console.log(`v3 anchor verifies: ${anchorFacts.ok}; v3 transition verifies: ${transitionFacts.ok}`);
```

<!-- readme-output -->
```text
v3 anchor verifies: true; v3 transition verifies: true
```
