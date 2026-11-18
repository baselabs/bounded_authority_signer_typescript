---
title: "HTTP client, browser and worker recipes"
category: Guides
---

# HTTP client, browser and worker recipes

These examples cover the class of hosts that issue grants or prove requests: services, command-line
clients, browsers and workers. Node HTTP and a dedicated browser worker are examples of that class.
They do not define a different authorization model. A production resource follows the verifier's
[HTTP resource-server guide](https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/guides/http-server.md).
It receives raw credentials and derives expected context itself; never trust client-supplied facts.

## Node HTTP client

The following complete transport recipe uses a real local HTTP server and the explicit loopback
profile. The server verifies the received envelope, method and target, then returns only a diagnostic
result. It performs no protected effect. Add host authorization, live revocation and atomic replay
reservation before an actual effect. For a remote HTTPS endpoint use `signReport` and the standard
verifier, keeping the same exact request binding. Header names and JSON fields here are a host
transport choice, not a new BAP wire format.

<!-- readme-sample: run -->
```ts
import { createServer } from "node:http";
import { once } from "node:events";
import { signGrant, signLocalLoopbackReport } from "@bounded-authority-protocol/signer";
import { checkLocalLoopbackHttpEnvelope, strUtf8 } from "@bounded-authority-protocol/verifier";
import { testKeyHandle } from "./key-handle.js";
const issuer = testKeyHandle("issuer-key", "issuer"), holder = testKeyHandle("holder-key");
const grant = await signGrant({ issuer: "https://issuer.example", grantId: "urn:example:grant:http",
  audiences: ["https://resource.example"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint: await holder.thumbprint(), operations: [{ name: "inspect", selectors: [{ kind: "all" }] }] }, issuer);
if (!grant.ok) throw new Error(grant.error);
const publicKey = await issuer.publicKey();
const nonce = "server-challenge", invocationId = "550e8400-e29b-41d4-a716-446655440000";
const server = createServer((req, res) => {
  const proof = String(req.headers["x-example-proof"] ?? "");
  const receivedGrant = String(req.headers["x-example-grant"] ?? "");
  const result = checkLocalLoopbackHttpEnvelope(strUtf8(receivedGrant), strUtf8(proof), {
    method: req.method!, targetUri: `http://127.0.0.1:${port}${req.url}`, invocationId,
    operation: "inspect", castArguments: { t: "null" },
    trustedIssuer: { keyId: "issuer-key", publicKey }, issuer: "https://issuer.example", audience: "https://resource.example",
    evaluationTime: 1500, clockSkew: 0, proofMaxAge: 300, nonce: { kind: "required", value: nonce },
  });
  res.writeHead(result.ok ? 200 : 401, { "content-type": "application/json" });
  res.end(JSON.stringify({ verified: result.ok }));
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
const address = server.address();
if (!address || typeof address === "string") throw new Error("listener address");
const port = address.port;
try {
  const targetUri = `http://127.0.0.1:${port}/inspect`;
  const proof = await signLocalLoopbackReport({ grantCompact: grant.value.grant, operation: "inspect",
    method: "POST", targetUri, invocationId, castArguments: { t: "null" }, nonce }, holder,
    { issuedAt: 1500, proofId: "urn:example:proof:http" });
  if (!proof.ok) throw new Error(proof.error);
  const headers = { "x-example-grant": new TextDecoder().decode(proof.value.grant), "x-example-proof": new TextDecoder().decode(proof.value.proof) };
  const success = await fetch(targetUri, { method: "POST", headers });
  if (success.status !== 200 || !(await success.json() as { verified: boolean }).verified) throw new Error("HTTP verification failed");
  const refusal = await fetch(targetUri + "-changed", { method: "POST", headers });
  if (refusal.status !== 401 || (await refusal.json() as { verified: boolean }).verified) throw new Error("changed URI accepted");
  console.log("HTTP: exact request verifies; changed target refused");
} finally {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
```
<!-- readme-output -->
```text
HTTP: exact request verifies; changed target refused
```

## Browser and dedicated worker

Generate the key inside a dedicated worker, keep its handle there, and expose a narrow message
protocol rather than exporting the handle. Bundle `signing-worker.ts` as `signing-worker.js` alongside
the page bundle. Both use the installed package. The real worker below signs a checkpoint and
returns only the compact; it never sends a private key to the page. Production workers should
validate message schemas and callers. Origin isolation and user approval remain host responsibilities.

Save `signing-worker.ts`:

<!-- readme-sample: file-dom signing-worker.ts -->
```ts
import { es256KeyHandle, signV3Anchor } from "@bounded-authority-protocol/signer";
self.onmessage = async () => {
  try {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const handle = await es256KeyHandle(pair, { keyId: "worker-key" });
    if (!handle.ok) throw new Error(handle.error);
    const anchor = await signV3Anchor({ anchorId: "urn:example:anchor:0", chainId: "urn:example:chain:worker", sequence: 0, chainHash: new Uint8Array(32) }, handle.value, { anchoredAt: 1500 });
    if (!anchor.ok) throw new Error(anchor.error);
    self.postMessage({ anchor: anchor.value.anchor, nonExtractable: !pair.privateKey.extractable });
  } catch (error) { self.postMessage({ error: String(error) }); }
};
```

In the page module, create the worker and terminate it after receiving the result:

<!-- readme-sample: run-dom -->
```ts
export {};
const worker = new Worker(new URL("./signing-worker.js", import.meta.url), { type: "module" });
try {
  const response = new Promise<{ anchor: Uint8Array; nonExtractable: boolean; error?: string }>((resolve, reject) => {
    worker.onmessage = (event) => resolve(event.data);
    worker.onerror = (event) => reject(new Error(event.message));
  });
  worker.postMessage("checkpoint");
  const result = await response;
  if (result.error || new TextDecoder().decode(result.anchor).split(".").length !== 3 || !result.nonExtractable) throw new Error("worker custody");
  console.log("worker signs with its own non-extractable P-256 key");
} finally { worker.terminate(); }
```
<!-- readme-output -->
```text
worker signs with its own non-extractable P-256 key
```

See [WebCrypto](webcrypto.md) and [security](security.md). Send raw credentials to your trusted
resource, never this page's verification result. A worker signature is not evidence of human approval.
