// T13: the key-handle factories' public types are structural (design §12.2, M3). A DOM CryptoKeyPair and
// Node's webcrypto.CryptoKeyPair are assignable without a cast, under the real tsconfig.browser.json (DOM,
// no ambient types) and the real tsconfig.json (the Node types). Revision R11 records the one place a
// cast IS needed: under @types/node, webcrypto.subtle.generateKey({ name: "Ed25519" }, ...) is typed
// Promise<CryptoKey> (the object literal { name: "Ed25519" } matches a symmetric-key overload first), so
// passing its result straight to a factory is TS2345, and a direct `as webcrypto.CryptoKeyPair` is TS2352;
// the README shows the double cast through unknown. The packed-tarball typecheck (test/tarball.ts) proves no public declaration needs a DOM
// or Node global type, with its red-proof.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const SRC_INDEX = join(REPO, "src/index.js");

function diagnostics(baseConfig: string, source: string): string[] {
  mkdirSync(join(REPO, "node_modules/.cache"), { recursive: true });
  const dir = mkdtempSync(join(REPO, "node_modules/.cache/bap-wc-types-"));
  try {
    const file = join(dir, "consumer.ts");
    writeFileSync(file, source.replaceAll("SRC_INDEX", SRC_INDEX));
    const config = join(dir, "tsconfig.json");
    writeFileSync(config, JSON.stringify({ extends: join(REPO, baseConfig), compilerOptions: { noEmit: true }, include: [], files: [file] }));
    const parsed = ts.getParsedCommandLineOfConfigFile(config, {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} });
    assert.ok(parsed, "the config parses");
    const program = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options });
    return ts.getPreEmitDiagnostics(program).map((d) => `${d.file ? d.file.fileName.replace(dir, "") : ""} TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const DOM_CONSUMER = `
import { ed25519KeyHandle, es256KeyHandle, type WebCryptoKeyPairLike, type WebCryptoHandleOptions } from "SRC_INDEX";
export async function fromPair(pair: CryptoKeyPair, opts: WebCryptoHandleOptions) {
  const a = await ed25519KeyHandle(pair, opts);
  const b = await es256KeyHandle(pair);
  const like: WebCryptoKeyPairLike = pair;
  return [a, b, like] as const;
}
export async function generated() {
  const ed = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const ec = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  return [await ed25519KeyHandle(ed, { keyId: "k", role: "issuer" }), await es256KeyHandle(ec)] as const;
}
`;

const NODE_CONSUMER = `
import { webcrypto } from "node:crypto";
import { ed25519KeyHandle, es256KeyHandle, type WebCryptoKeyPairLike } from "SRC_INDEX";
export async function fromPair(pair: webcrypto.CryptoKeyPair) {
  const like: WebCryptoKeyPairLike = pair;
  return [await ed25519KeyHandle(pair), await es256KeyHandle(pair), like] as const;
}
export async function generated() {
  // The cast the README shows: @types/node types this call as Promise<CryptoKey>.
  const ed = (await webcrypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as unknown as webcrypto.CryptoKeyPair;
  const ec = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  return [await ed25519KeyHandle(ed), await es256KeyHandle(ec)] as const;
}
`;

const NODE_UNCAST = `
import { webcrypto } from "node:crypto";
import { ed25519KeyHandle } from "SRC_INDEX";
export async function generated() {
  return ed25519KeyHandle(await webcrypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]));
}
`;

test("T13: a DOM CryptoKeyPair, and DOM generateKey results, pass to both factories without a cast (tsconfig.browser.json)", () => {
  assert.deepEqual(diagnostics("tsconfig.browser.json", DOM_CONSUMER), []);
});

test("T13: Node's webcrypto.CryptoKeyPair passes to both factories without a cast (tsconfig.json, @types/node)", () => {
  assert.deepEqual(diagnostics("tsconfig.json", NODE_CONSUMER), []);
});

test("T13 (R11): under @types/node, webcrypto.subtle.generateKey({ name: \"Ed25519\" }) passed uncast is TS2345 (typed Promise<CryptoKey>)", (t) => {
  const version = (JSON.parse(readFileSync(join(REPO, "node_modules/@types/node/package.json"), "utf8")) as { version: string }).version;
  const found = diagnostics("tsconfig.json", NODE_UNCAST);
  assert.equal(found.length, 1, found.join("\n"));
  assert.match(found[0]!, /TS2345: Argument of type 'CryptoKey' is not assignable to parameter of type 'WebCryptoKeyPairLike'/);
  t.diagnostic(`@types/node ${version}: ${found[0]}`);
});

test("T13: the emitted webcrypto.d.ts names no DOM or Node global type (the declared parameter is structural)", () => {
  const parsed = ts.getParsedCommandLineOfConfigFile(join(REPO, "tsconfig.build.json"), {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} });
  assert.ok(parsed);
  const emitted = new Map<string, string>();
  const program = ts.createProgram({
    rootNames: [join(REPO, "src/index.ts")],
    options: { ...parsed.options, declaration: true, emitDeclarationOnly: true, removeComments: true, sourceMap: false, declarationMap: false, noEmit: false },
  });
  const result = program.emit(undefined, (name, text) => emitted.set(name.replace(/\\/g, "/").replace(/^.*\/dist\//, "dist/"), text));
  assert.deepEqual(result.diagnostics.map((d) => ts.flattenDiagnosticMessageText(d.messageText, " ")), []);
  const dts = emitted.get("dist/src/webcrypto.d.ts");
  assert.ok(dts !== undefined, [...emitted.keys()].join(", "));
  assert.match(dts, /export declare function ed25519KeyHandle\(pair: WebCryptoKeyPairLike, opts\?: WebCryptoHandleOptions\)/);
  for (const name of ["CryptoKey", "CryptoKeyPair", "SubtleCrypto", "KeyObject", "webcrypto"]) {
    assert.ok(!new RegExp(`\\b${name}\\b`).test(dts), `${name} appears in the emitted declarations:\n${dts}`);
  }
});
