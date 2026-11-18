# @bounded-authority-protocol/signer

[![npm](https://img.shields.io/npm/v/@bounded-authority-protocol/signer)](https://www.npmjs.com/package/@bounded-authority-protocol/signer)
[![CI](https://github.com/baselabs/bounded_authority_signer_typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/baselabs/bounded_authority_signer_typescript/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

The signing side of the Bounded Authority Protocol, in TypeScript. An issuer uses it to sign a
**grant**: the holder of one key may invoke named operations, with constraints on their arguments,
at named resources, within a time window. The holder (an agent, an app, a service) uses it to sign a **proof** that binds
one request to that grant. A resource server checks the pair with
[`@bounded-authority-protocol/verifier`](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
and gets facts back. The same package signs boundary anchors and key transitions for audit chains.

You pass a **key handle**: an object whose `sign()` reaches your own key custody (a KMS, an HSM, a
WebCrypto key, or an in-process key in tests). The private key never enters the library, and every
handle method may be async.

OAuth 2.0 is an authorization framework for delegated, scoped access. BAP complements OAuth by
binding a holder's authority to the method, URI, operation and JCS typed projection of
`cast_arguments` through a signed grant and holder proof.
The verifier checks those bytes against caller-supplied trust and context. The host runtime
separately applies authorization policy, revocation checks, and replay reservation.

**Try it in your browser first:** the [envelope playground](https://baselabs.github.io/bounded_authority_signer_typescript/)
runs this package and the verifier in the page, with keys your browser generates.
Browse the [API reference](https://baselabs.github.io/bounded_authority_signer_typescript/api/)
for searchable signatures and types, stamped with the package version.

What it is not: it does not verify (that is the verifier package), decide whether a request is
allowed, store keys, transport anything, or track replay and revocation (that is your authority
runtime).

## When to use it

Use it when an issuer or holder needs to sign BAP grants, request proofs, anchors or key transitions through caller-owned custody.

## When not to use it

Use a stateful authority runtime for authorization, trusted-key selection, live revocation and replay reservation. This package supplies signed bytes, not an execution decision.

## Trust boundary

An issuer role is a local handle property, not a credential. The resource selects trusted issuer keys. A successful signer result checks the signature against the handle’s public key; it does not authenticate the input grant or evaluate its selectors. Browser verification is display-only.

## Install

```bash
npm install @bounded-authority-protocol/signer@2.0.0 @bounded-authority-protocol/verifier@2.0.0
```

Node.js 22 or later; ESM. Install both packages whenever your code imports both.

## Quickstart


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

## Documentation

1. [Quickstart](docs/guides/getting-started.md)
2. [Concepts and trust boundaries](docs/guides/concepts.md)
3. [API reference](docs/guides/api-overview.md)
4. [Choose a contract major](docs/guides/contract-majors.md)
5. [Contract-major 2: Ed25519 with range selectors](docs/guides/contract-major-2.md)
6. [Contract-major 3: ES256](docs/guides/contract-major-3.md)
7. [The key-handle contract](docs/guides/key-custody.md)
8. [WebCrypto key handles](docs/guides/webcrypto.md)
9. [Keys in a KMS or HSM](docs/guides/remote-custody.md)
10. [Sign for a local app (loopback)](docs/guides/local-loopback.md)
11. [Anchor a chain and rotate its key](docs/guides/rotate-keys.md)
12. [Browsers, Deno, Bun and workers](docs/guides/runtimes.md)
13. [Security for integrators](docs/guides/security.md)
14. [Operate signing custody](docs/guides/operations.md)
15. [Telemetry and observability](docs/guides/telemetry.md)
16. [Errors](docs/guides/errors.md)
17. [HTTP client, browser and worker recipes](docs/guides/recipes.md)
18. [Test your integration](docs/guides/test-your-integration.md)
19. [Versioning and compatibility](docs/guides/upgrading.md)
20. [FAQ](docs/guides/faq.md)
21. [Glossary](docs/guides/glossary.md)
22. [Cheatsheet](docs/guides/cheatsheet.md)
23. [How this package is tested](docs/guides/qualification.md)

## Notebooks

Jupyter notebooks use the Deno kernel and exact published npm releases. See [launch instructions](docs/notebooks/README.md).

- [Grant and proof](docs/notebooks/grant-and-proof.ipynb)
- [Bounded selectors and ES256](docs/notebooks/bounded-selectors-es256.ipynb)
- [Key custody and refusals](docs/notebooks/key-custody.ipynb)
- [Local loopback](docs/notebooks/local-loopback.ipynb)
- [Anchors and key transitions](docs/notebooks/anchors-and-transitions.ipynb)

## Security

Report vulnerabilities through [SECURITY.md](SECURITY.md). Read [usage rules](usage-rules.md) before integrating.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for qualification commands and [CHANGELOG.md](CHANGELOG.md) for release history.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
