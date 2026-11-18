---
title: "Sign for a local app (loopback)"
category: Guides
---

# Sign for a local app (loopback)


`signLocalLoopbackReport` signs the local-loopback application-proof profile
(`ba+loopback-proof`), for a desktop or local app that serves a protocol endpoint on the loopback
interface. The profile is selected by the function name, never inferred. The app issues a nonce,
the proof must carry it, and the target must be exactly `http://127.0.0.1[:port]/…` or
`http://[::1][:port]/…` (`localhost` and every other spelling are `producer_error`):

<!-- readme-sample: run -->
```ts
import { signGrant, signLocalLoopbackReport } from "@bounded-authority-protocol/signer";
import { checkLocalLoopbackHttpEnvelope, strUtf8, type Tagged } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const issuer = testKeyHandle("issuer-key-1", "issuer");
const helper = testKeyHandle("helper-key-1"); // an agent on the same machine

const grant = await signGrant({
  issuer: "https://issuer.example", grantId: "urn:example:grant:notes",
  audiences: ["https://notes.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_229_200,
  holderThumbprint: await helper.thumbprint(),
  operations: [{ name: "open_note", selectors: [{ kind: "all" }] }],
}, issuer);
if (!grant.ok) throw new Error(`signGrant: ${grant.error}`);

const nonce = "c8f2a1"; // issued by the local app for this request
const request = {
  method: "POST", targetUri: "http://127.0.0.1:47321/rpc",
  invocationId: "9c4b2e7a-1d3f-4c5b-a6e7-8f9a0b1c2d3e", operation: "open_note",
  castArguments: { t: "object", v: new Map<string, Tagged>([["title", { t: "string", v: strUtf8("Groceries") }]]) } satisfies Tagged,
};
const envelope = await signLocalLoopbackReport({ grantCompact: grant.value.grant, ...request, nonce }, helper, { issuedAt: 1_767_225_660 });
if (!envelope.ok) throw new Error(`signLocalLoopbackReport: ${envelope.error}`);

const facts = checkLocalLoopbackHttpEnvelope(envelope.value.grant, envelope.value.proof, {
  ...request,
  trustedIssuer: { keyId: "issuer-key-1", publicKey: await issuer.publicKey() },
  issuer: "https://issuer.example", audience: "https://notes.example",
  evaluationTime: 1_767_225_700, clockSkew: 60, proofMaxAge: 300,
  nonce: { kind: "required", value: nonce },
});
console.log(`loopback envelope verifies: ${facts.ok}`);
```

<!-- readme-output -->
```text
loopback envelope verifies: true
```
