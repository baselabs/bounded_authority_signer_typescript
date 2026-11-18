---
title: "Contract-major 2: Ed25519 with range selectors"
category: Guides
---

# Contract-major 2: Ed25519 with range selectors


The v2 signers take the same `KeyHandle` and emit the verifier's v2 format: `v: 2` payloads, the
`BAP2-*` domain separators, and the `lte` and `gte` selectors with an `int`- or `float`-tagged bound.
They compose through the verifier's own v2 signing inputs and `v2.assembleCompact`. Each major
verifies only its own bytes: `checkEnvelope` refuses a v2 envelope and `v2.checkEnvelope` refuses a
v1 one. A `float` bound must be non-integral: canonical JSON writes `10.0` as `10`, which decodes as
an `int`, so every grant signer (all three majors) refuses a float-tagged integral number (`0.0`,
`-0.0`, `10.0`) anywhere in a selector value with `producer_error` (see
[Float-tagged integral selector values](errors.md#float-tagged-integral-selector-values)); write it as an
`int`. Here a
home assistant may set a thermostat between 18.5 and 24.5 °C:

<!-- readme-sample: run -->
```ts
import { signV2Grant, signV2Report } from "@bounded-authority-protocol/signer";
import { v2, type Tagged } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";

const home = testKeyHandle("home-issuer-1", "issuer");
const assistant = testKeyHandle("assistant-key-1");

const grant = await signV2Grant({
  issuer: "https://home.example", grantId: "urn:example:grant:thermostat",
  audiences: ["https://thermostat.example"],
  issuedAt: 1_767_225_600, notBefore: 1_767_225_600, expiresAt: 1_767_312_000,
  holderThumbprint: await assistant.thumbprint(),
  operations: [{ name: "set_temperature", selectors: [
    { kind: "gte", path: ["celsius"], value: { t: "float", v: 18.5 } },
    { kind: "lte", path: ["celsius"], value: { t: "float", v: 24.5 } },
  ] }],
}, home);
if (!grant.ok) throw new Error(`signV2Grant: ${grant.error}`);
const grantCompact = grant.value.grant;

async function setTemperature(celsius: number): Promise<boolean> {
  const request = {
    method: "PUT", targetUri: "https://thermostat.example/setpoint",
    invocationId: "3b9e1c52-8d4f-4a1e-b7c2-5e6f7a8b9c0d", operation: "set_temperature",
    castArguments: { t: "object", v: new Map<string, Tagged>([["celsius", { t: "float", v: celsius }]]) } satisfies Tagged,
  };
  const envelope = await signV2Report({ grantCompact, ...request }, assistant, { issuedAt: 1_767_225_660 });
  if (!envelope.ok) throw new Error(`signV2Report: ${envelope.error}`);
  return v2.checkEnvelope(envelope.value.grant, envelope.value.proof, {
    ...request,
    trustedIssuer: { keyId: "home-issuer-1", publicKey: await home.publicKey() },
    issuer: "https://home.example", audience: "https://thermostat.example",
    evaluationTime: 1_767_225_700, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
  }).ok;
}

console.log(`21.5 °C verifies: ${await setTemperature(21.5)}`);
console.log(`30.5 °C verifies: ${await setTemperature(30.5)}`);
```

<!-- readme-output -->
```text
21.5 °C verifies: true
30.5 °C verifies: false
```

The local-loopback profile belongs to contract-major 1 and has no v2 form.
