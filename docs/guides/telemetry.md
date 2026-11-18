---
title: "Telemetry and observability"
category: Guides
---

# Telemetry and observability

Events contain only `kind` and `phase`. A call emits `start`, then exactly one `stop` or `error`
when it resolves. Listener exceptions are ignored. Factories emit no signing events. See
[operations](operations.md#event-ordering) for concurrency and deadline behavior.

Use one closure per call for elapsed time and correlation. Export counters labeled only by bounded
operation kind, terminal phase and the returned closed error code. Host metrics may separately
track custody latency, retries and availability. Never label by grant ID, holder thumbprint,
invocation ID, URI, nonce, arguments, compact, signature or custody response. Host authorization,
replay and revocation metrics belong to the host; this package cannot report them.

This example checks success and failure ordering, including a listener that throws. It uses real
keys and a real invalid input, without a telemetry service or a simulated custodian.

<!-- readme-sample: run -->
```ts
import { signAnchor } from "@bounded-authority-protocol/signer";
import { testKeyHandle } from "./key-handle.js";
const input = { anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:1", sequence: 0, chainHash: new Uint8Array(32) };
const phases: string[] = [];
const result = await signAnchor(input, testKeyHandle("audit-key"), {
  anchoredAt: 1500, onEvent: (event) => { phases.push(`${event.kind}:${event.phase}`); throw new Error("listener failure"); },
});
if (!result.ok || phases.join(",") !== "anchor:start,anchor:stop") throw new Error("success event contract");
const failed: string[] = [];
const refusal = await signAnchor({ ...input, chainHash: new Uint8Array(31) }, testKeyHandle("audit-key"), {
  onEvent: (event) => { failed.push(event.phase); },
});
if (refusal.ok || refusal.error !== "invalid_anchor" || failed.join(",") !== "start,error") throw new Error("error event contract");
console.log("success: start,stop; refusal: start,error; throwing listener ignored");
```
<!-- readme-output -->
```text
success: start,stop; refusal: start,error; throwing listener ignored
```
