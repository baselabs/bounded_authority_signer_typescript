// Erratum 6, the producer half (REQ1/REQ2/REQ3-SIGNING-integral-float-selector): RFC 8785 writes an
// integral float (0.0, -0.0, 10.0) as integer text, which decodes integer-tagged, so a grant whose
// selector value holds a float-tagged integral number at any depth would not mean what the issuer
// gave. Every grant signer refuses one with producer_error before sign() is called: equals values,
// one_of members, and the contract-major 2/3 lte/gte bounds. Non-integral floats and integers still
// sign, and the signed grant decodes back to exactly the tagged value given (so a zero is only ever
// emitted integer-tagged).
import { test } from "node:test";
import assert from "node:assert/strict";
import { base64urlDecode, jsonDecode, strUtf8, v2, v3, verifyGrant, type Tagged } from "@bounded-authority-protocol/verifier";
import { signGrant, signV2Grant, signV3Grant, type Es256KeyHandle, type KeyHandle } from "../src/index.js";
import { ecHandle, ecKey, edHandle, edKey } from "./lanes/keys.js";

const ISS = "https://issuer.example.test";
const AUD = "https://resource.example.test";

const int = (v: number): Tagged => ({ t: "int", v });
const float = (v: number): Tagged => ({ t: "float", v });
const obj = (entries: [string, Tagged][]): Tagged => ({ t: "object", v: new Map(entries) });
const arr = (...items: Tagged[]): Tagged => ({ t: "array", v: items });
const str = (s: string): Tagged => ({ t: "string", v: strUtf8(s) });

type Selector =
  | { kind: "equals"; path: string[]; value: Tagged }
  | { kind: "one_of"; path: string[]; values: Tagged[] }
  | { kind: "lte" | "gte"; path: string[]; value: Tagged };

const grantInput = (holderThumbprint: string, selector: Selector) => ({
  issuer: ISS, grantId: "urn:example:grant:float", audiences: [AUD], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint, operations: [{ name: "transfer", selectors: [selector] }],
});

interface Major {
  readonly name: string;
  readonly ranges: boolean;
  sign(selector: Selector): Promise<{ result: { ok: boolean; error?: string; value?: { grant: Uint8Array } }; signCalls: number; verified(grant: Uint8Array): boolean }>;
}

function counted<H extends KeyHandle | Es256KeyHandle>(handle: H, calls: { count: number }): H {
  return { ...handle, sign: (m: Uint8Array) => { calls.count += 1; return handle.sign(m); } };
}

const trustedAt = { issuer: ISS, audience: AUD, evaluationTime: 1500, clockSkew: 60 };

const MAJORS: readonly Major[] = [
  {
    name: "v1", ranges: false,
    async sign(selector) {
      const issuer = edKey();
      const calls = { count: 0 };
      const result = await signGrant(grantInput(edKey().thumbprint, selector) as never, counted(edHandle(issuer, { keyId: "issuer-key", role: "issuer" }), calls));
      return { result, signCalls: calls.count, verified: (g) => verifyGrant(g, { keyId: "issuer-key", publicKey: issuer.publicKey }, trustedAt).ok };
    },
  },
  {
    name: "v2", ranges: true,
    async sign(selector) {
      const issuer = edKey();
      const calls = { count: 0 };
      const result = await signV2Grant(grantInput(edKey().thumbprint, selector), counted(edHandle(issuer, { keyId: "issuer-key", role: "issuer" }), calls));
      return { result, signCalls: calls.count, verified: (g) => v2.verifyGrant(g, { keyId: "issuer-key", publicKey: issuer.publicKey }, trustedAt).ok };
    },
  },
  {
    name: "v3", ranges: true,
    async sign(selector) {
      const issuer = ecKey();
      const calls = { count: 0 };
      const result = await signV3Grant(grantInput(ecKey().thumbprint, selector), counted(ecHandle(issuer, { keyId: "issuer-key", role: "issuer" }), calls));
      return { result, signCalls: calls.count, verified: (g) => v3.verifyGrant(g, { keyId: "issuer-key", publicKey: issuer.publicKey }, trustedAt).ok };
    },
  },
];

// Selector values holding a float-tagged integral number, top level and nested. 1e-400 underflows to
// zero when parsed, so it is the float zero too.
const INTEGRAL_FLOATS: readonly [string, Tagged][] = [
  ["0.0", float(0)],
  ["-0.0", float(-0)],
  ["1e-400", float(Number("1e-400"))],
  ["10.0", float(10)],
  ["-3.0", float(-3)],
  ["2^53 - 1 as a float", float(Number.MAX_SAFE_INTEGER)],
  ["0.0 in an object", obj([["amount", float(0)]])],
  ["10.0 in an array in an object", obj([["limits", arr(int(1), str("x"), float(10))]])],
  ["-0.0 three levels down", arr(obj([["a", arr(float(-0))]]))],
];

// Selector values that sign: integers (zero included) and non-integral floats, top level and nested.
const SIGNABLE: readonly [string, Tagged][] = [
  ["int 0", int(0)],
  ["int 10", int(10)],
  ["int -5", int(-5)],
  ["float 10.5", float(10.5)],
  ["float -0.25", float(-0.25)],
  ["float 1e-7", float(1e-7)],
  ["nested int 0 and float 0.5", obj([["a", int(0)], ["b", arr(float(0.5), str("x"))]])],
];

const selectorsFor = (m: Major, value: Tagged): [string, Selector][] => [
  ["equals", { kind: "equals", path: ["amount"], value }],
  ["one_of member", { kind: "one_of", path: ["amount"], values: [int(1), value] }],
  ...(m.ranges && (value.t === "int" || value.t === "float")
    ? [["lte", { kind: "lte", path: ["amount"], value }], ["gte", { kind: "gte", path: ["amount"], value }]] as [string, Selector][]
    : []),
];

// The selector values of the signed grant's first operation, as the verifier's decoder tags them.
function signedSelectorValues(grant: Uint8Array): Tagged[] {
  const payloadSegment = new TextDecoder().decode(grant).split(".")[1]!;
  const payload = jsonDecode(base64urlDecode(strUtf8(payloadSegment)));
  const member = (v: Tagged, key: string): Tagged => {
    assert.equal(v.t, "object");
    const found = (v as { v: ReadonlyMap<string, Tagged> }).v.get(key);
    assert.ok(found, `member ${key}`);
    return found;
  };
  const items = (v: Tagged): Tagged[] => { assert.equal(v.t, "array"); return (v as { v: Tagged[] }).v; };
  const selector = items(member(items(member(payload, "operations"))[0]!, "selectors"))[0]!;
  const kind = new TextDecoder().decode((member(selector, "kind") as { v: Uint8Array }).v);
  return kind === "one_of" ? items(member(selector, "values")) : [member(selector, "value")];
}

for (const m of MAJORS) {
  test(`${m.name}: a float-tagged integral selector value is producer_error and sign() is never called`, async () => {
    for (const [label, value] of INTEGRAL_FLOATS) {
      for (const [where, selector] of selectorsFor(m, value)) {
        const { result, signCalls } = await m.sign(selector);
        assert.deepEqual(result, { ok: false, error: "producer_error" }, `${m.name} ${where}: ${label}`);
        assert.equal(signCalls, 0, `${m.name} ${where}: ${label}: sign() is never called`);
      }
    }
  });

  test(`${m.name}: integers and non-integral floats sign, verify, and decode back with the tag given`, async () => {
    for (const [label, value] of SIGNABLE) {
      for (const [where, selector] of selectorsFor(m, value)) {
        const { result, verified } = await m.sign(selector);
        assert.equal(result.ok, true, `${m.name} ${where}: ${label}: ${result.error}`);
        const grant = result.value!.grant;
        assert.equal(verified(grant), true, `${m.name} ${where}: ${label}: the verifier accepts the grant`);
        const given = selector.kind === "one_of" ? selector.values : [selector.value];
        assert.deepEqual(signedSelectorValues(grant), given, `${m.name} ${where}: ${label}: the signed value decodes to the value given`);
      }
    }
  });
}
