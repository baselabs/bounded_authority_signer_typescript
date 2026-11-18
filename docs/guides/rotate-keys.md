---
title: "Anchor a chain and rotate its key"
category: Guides
---

# Anchor a chain and rotate its key


A boundary anchor signs a checkpoint of a hash chain (an audit log, for example): its id, sequence
number and hash at that sequence. A key transition, signed by the current key, names the key that
takes over and when. Both need `keyIdentity()` and are role-agnostic. The verifier checks them
with `verifyHistoricalAnchor` and `verifyKeyTransition`:

<!-- readme-sample: run -->
```ts
import { signAnchor, signKeyTransition } from "@bounded-authority-protocol/signer";
import { publicKeyThumbprintRaw, verifyHistoricalAnchor, verifyKeyTransition } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const current = testKeyHandle("audit-key-1");
const next = testKeyHandle("audit-key-2");
const chainHash = new Uint8Array(32); // the chain's hash at this sequence (all zero at genesis)

const anchor = await signAnchor(
  { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:audit-log", sequence: 0, chainHash },
  current, { anchoredAt: 1_767_225_600 },
);
if (!anchor.ok) throw new Error(`signAnchor: ${anchor.error}`);

// Rotate: the current key signs the handover to the next key.
const transition = await signKeyTransition({
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:audit-log",
  effectiveAt: 1_767_312_000, nextKeyId: "audit-key-2", nextPublicKey: await next.publicKey(),
}, current);
if (!transition.ok) throw new Error(`signKeyTransition: ${transition.error}`);

const currentKey = { keyId: "audit-key-1", publicKey: await current.publicKey(), validFrom: 0, validBefore: null };
const nextKey = { keyId: "audit-key-2", publicKey: await next.publicKey(), validFrom: 1_767_312_000, validBefore: null };
const anchorFacts = verifyHistoricalAnchor(anchor.value.anchor, currentKey, {
  anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:audit-log", keyId: "audit-key-1",
  sequence: 0, anchoredAt: 1_767_225_600, chainHash, keyFingerprint: publicKeyThumbprintRaw(currentKey.publicKey),
});
const transitionFacts = verifyKeyTransition(transition.value.keyTransition, currentKey, nextKey, {
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:audit-log", effectiveAt: 1_767_312_000,
  currentKeyId: "audit-key-1", nextKeyId: "audit-key-2",
  currentKeyFingerprint: publicKeyThumbprintRaw(currentKey.publicKey),
  nextKeyFingerprint: publicKeyThumbprintRaw(nextKey.publicKey),
});
console.log(`anchor verifies: ${anchorFacts.ok}; transition verifies: ${transitionFacts.ok}`);
```

<!-- readme-output -->
```text
anchor verifies: true; transition verifies: true
```

On contract-major 2, `signV2Anchor` and `signV2KeyTransition` take the same inputs and the same
handle, and `v2.verifyHistoricalAnchor` and `v2.verifyKeyTransition` check them:

<!-- readme-sample: run -->
```ts
import { signV2Anchor, signV2KeyTransition } from "@bounded-authority-protocol/signer";
import { publicKeyThumbprintRaw, v2 } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const current = testKeyHandle("audit-key-1");
const next = testKeyHandle("audit-key-2");
const chainHash = new Uint8Array(32);

const anchor = await signV2Anchor(
  { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:audit-log", sequence: 0, chainHash },
  current, { anchoredAt: 1_767_225_600 },
);
const transition = await signV2KeyTransition({
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:audit-log",
  effectiveAt: 1_767_312_000, nextKeyId: "audit-key-2", nextPublicKey: await next.publicKey(),
}, current);
if (!anchor.ok || !transition.ok) throw new Error("signing failed");

const currentKey = { keyId: "audit-key-1", publicKey: await current.publicKey(), validFrom: 0, validBefore: null };
const nextKey = { keyId: "audit-key-2", publicKey: await next.publicKey(), validFrom: 1_767_312_000, validBefore: null };
const anchorFacts = v2.verifyHistoricalAnchor(anchor.value.anchor, currentKey, {
  anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:audit-log", keyId: "audit-key-1",
  sequence: 0, anchoredAt: 1_767_225_600, chainHash, keyFingerprint: publicKeyThumbprintRaw(currentKey.publicKey),
});
const transitionFacts = v2.verifyKeyTransition(transition.value.keyTransition, currentKey, nextKey, {
  transitionId: "urn:example:transition:1", chainId: "urn:example:chain:audit-log", effectiveAt: 1_767_312_000,
  currentKeyId: "audit-key-1", nextKeyId: "audit-key-2",
  currentKeyFingerprint: publicKeyThumbprintRaw(currentKey.publicKey),
  nextKeyFingerprint: publicKeyThumbprintRaw(nextKey.publicKey),
});
console.log(`v2 anchor verifies: ${anchorFacts.ok}; v2 transition verifies: ${transitionFacts.ok}`);
```

<!-- readme-output -->
```text
v2 anchor verifies: true; v2 transition verifies: true
```

To rotate a holder or issuer key, you also build a new handle: a handle reports one public key.
