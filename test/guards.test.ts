// The no-Node-API guards and their red-proofs, each against the REAL configuration file: the browser
// typecheck (tsconfig.browser.json), the library lint (eslint.config.js), and the browser-bundle guard
// (tools/browser-guard.mjs: esbuild with platform "browser", then a scope-aware unresolved-globals scan
// of the bundle with ESLint no-undef). Every banned form has its own probe that must trip its rule, the
// handle API and the signer's own clock and proof-id defaults must not trip anything, and the real src/
// must be clean. The real-runtime lanes stay the behavioral backstop.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { transform } from "esbuild";
import { ESLint } from "eslint";
import ts from "typescript";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const eslint = new ESLint({ cwd: REPO, overrideConfigFile: join(REPO, "eslint.config.js") });

async function lintRules(code: string, filePath: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: join(REPO, filePath) });
  return (result?.messages ?? []).map((m) => m.ruleId ?? `fatal: ${m.message}`);
}

// ---- lint: one probe per banned form ----

const LINT_PROBES: ReadonlyArray<readonly [string, string, string]> = [
  // Node builtins, prefixed and bare.
  ["import node:crypto", 'import { createHash } from "node:crypto";\nexport const p = createHash;', "no-restricted-imports"],
  ["import crypto", 'import { createHash } from "crypto";\nexport const p = createHash;', "no-restricted-imports"],
  ["import node:buffer", 'import { Buffer as B } from "node:buffer";\nexport const p = B;', "no-restricted-imports"],
  ["import node:module", 'import { createRequire } from "node:module";\nexport const p = createRequire;', "no-restricted-imports"],
  ["import node:util", 'import { inspect } from "node:util";\nexport const p = inspect;', "no-restricted-imports"],
  ["import node:fs", 'import { readFileSync } from "node:fs";\nexport const p = readFileSync;', "no-restricted-imports"],
  ["import path", 'import { join } from "path";\nexport const p = join;', "no-restricted-imports"],
  ["re-export node:crypto", 'export { createHash } from "node:crypto";', "no-restricted-imports"],
  // Node globals.
  ["Buffer", 'export const p = Buffer.from("x");', "no-restricted-globals"],
  ["process", "export const p = process.version;", "no-restricted-globals"],
  ["global", "export const p = global;", "no-restricted-globals"],
  ["require (global)", 'export const p = require;', "no-restricted-globals"],
  ["require() (call)", 'export const p = require("x");', "no-restricted-syntax"],
  ["module", "export const p = module;", "no-restricted-globals"],
  ["exports", "export const p = exports;", "no-restricted-globals"],
  ["__dirname", "export const p = __dirname;", "no-restricted-globals"],
  ["__filename", "export const p = __filename;", "no-restricted-globals"],
  ["setImmediate", "export const p = setImmediate;", "no-restricted-globals"],
  ["globalThis.Buffer", "export const p = globalThis.Buffer;", "no-restricted-properties"],
  ["globalThis.process", "export const p = globalThis.process;", "no-restricted-properties"],
  ["globalThis.require", "export const p = globalThis.require;", "no-restricted-properties"],
  ["globalThis['Buffer']", 'export const p = globalThis["Buffer"];', "no-restricted-properties"],
  // A cast hides the object from no-restricted-properties; the property name alone is banned.
  ["cast globalThis.Buffer", 'export const p = (globalThis as unknown as { Buffer: { from(s: string): Uint8Array } }).Buffer.from("x");', "no-restricted-syntax"],
  ["cast globalThis.process", 'export const p = (globalThis as unknown as { process: { version: string } }).process.version;', "no-restricted-syntax"],
  ["cast globalThis.require", 'export const p = (globalThis as unknown as { require(s: string): unknown }).require("x");', "no-restricted-syntax"],
  ["any object ['Buffer']", 'const o: Record<string, unknown> = globalThis;\nexport const p = o["Buffer"];', "no-restricted-syntax"],
  ["window.process", "export const p = window.process;", "no-restricted-properties"],
  ["self.Buffer", "export const p = self.Buffer;", "no-restricted-properties"],
  // Network: the signer is not a transport.
  ["fetch", 'export const p = fetch("https://example.test/");', "no-restricted-globals"],
  ["XMLHttpRequest", "export const p = new XMLHttpRequest();", "no-restricted-globals"],
  ["WebSocket", 'export const p = new WebSocket("wss://example.test/");', "no-restricted-globals"],
  // Dynamic code and dynamic loading.
  ["dynamic import()", 'export const p = import("./api.js");', "no-restricted-syntax"],
  ["eval", 'export const p = eval("1");', "no-eval"],
  ["new Function", 'export const p = new Function("return 1");', "no-new-func"],
  ["Function()", 'export const p = Function("return 1");', "no-new-func"],
  ["implied eval", 'globalThis.setTimeout("1", 0);', "no-implied-eval"],
  // The private key never enters the library: no @noble, no WebCrypto, no key-generation entry point.
  ["@noble/ed25519", 'import { sign } from "@noble/ed25519";\nexport const p = sign;', "no-restricted-imports"],
  ["@noble/curves", 'import { p256 } from "@noble/curves/nist.js";\nexport const p = p256;', "no-restricted-imports"],
  ["@noble/hashes", 'import { sha256 } from "@noble/hashes/sha2.js";\nexport const p = sha256;', "no-restricted-imports"],
  ["crypto.subtle", "export const p = crypto.subtle;", "no-restricted-syntax"],
  ["globalThis.crypto.subtle", "export const p = globalThis.crypto.subtle;", "no-restricted-syntax"],
  [".generateKey", 'export const p = (c: { generateKey(): void }) => c.generateKey();', "no-restricted-properties"],
  [".importKey", 'export const p = (c: { importKey(): void }) => c.importKey();', "no-restricted-properties"],
  [".exportKey", 'export const p = (c: { exportKey(): void }) => c.exportKey();', "no-restricted-properties"],
  [".deriveKey", 'export const p = (c: { deriveKey(): void }) => c.deriveKey();', "no-restricted-properties"],
  [".keygen", 'export const p = (c: { keygen(): void }) => c.keygen();', "no-restricted-properties"],
  [".getPublicKey", 'export const p = (c: { getPublicKey(): void }) => c.getPublicKey();', "no-restricted-properties"],
  [".randomSecretKey", 'export const p = (c: { randomSecretKey(): void }) => c.randomSecretKey();', "no-restricted-properties"],
  [".getSharedSecret", 'export const p = (c: { getSharedSecret(): void }) => c.getSharedSecret();', "no-restricted-properties"],
];

for (const [label, code, rule] of LINT_PROBES) {
  test(`lint probe trips ${rule}: ${label}`, async () => {
    assert.ok((await lintRules(code, "src/guard-probe.ts")).includes(rule), `${label} must trip ${rule}`);
  });
}

test("lint: the caller's handle.sign(), crypto.randomUUID() and Date.now() stay allowed in src/", async () => {
  const code = [
    "export const p = async (h: { sign(m: Uint8Array): Uint8Array | Promise<Uint8Array> }) => [",
    "  await h.sign(new Uint8Array(1)), crypto.randomUUID(), Math.floor(Date.now() / 1000),",
    "];",
  ].join("\n");
  assert.deepEqual(await lintRules(code, "src/guard-probe.ts"), []);
});

test("the real src/ is lint-clean under these rules", async () => {
  const results = await eslint.lintFiles(["src/**/*.ts"]);
  assert.ok(results.length >= 8, `linted ${results.length} files`);
  const problems = results.flatMap((r) => r.messages.map((m) => `${r.filePath}:${m.line} ${m.ruleId} ${m.message}`));
  assert.deepEqual(problems, []);
});

// ---- browser typecheck: the real tsconfig.browser.json, extended by one fixture at a time ----

function browserDiagnostics(extraFile: string | null): string[] {
  const base = join(REPO, "tsconfig.browser.json");
  assert.ok(existsSync(base), "tsconfig.browser.json exists");
  mkdirSync(join(REPO, "node_modules/.cache"), { recursive: true });
  const dir = mkdtempSync(join(REPO, "node_modules/.cache/bap-guard-"));
  const config = join(dir, "tsconfig.json");
  try {
    writeFileSync(config, JSON.stringify({ extends: base, files: extraFile === null ? [] : [join(REPO, extraFile)] }));
    const parsed = ts.getParsedCommandLineOfConfigFile(config, {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} });
    assert.ok(parsed, "the config parses");
    const program = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options });
    return ts.getPreEmitDiagnostics(program).map((d) => {
      const where = d.file ? d.file.fileName.replace(REPO, "") : "";
      return `${where} TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("browser typecheck: the real src/ is clean under DOM + ES2022 with no types and skipLibCheck false", () => {
  assert.deepEqual(browserDiagnostics(null), []);
});

for (const [fixture, needle] of [
  ["test/fixtures/guard/buffer-global.ts", "Cannot find name 'Buffer'"],
  ["test/fixtures/guard/process-global.ts", "Cannot find name 'process'"],
  ["test/fixtures/guard/node-crypto-import.ts", "'node:crypto'"],
] as const) {
  test(`browser typecheck red-proof: ${fixture} is refused`, () => {
    const diagnostics = browserDiagnostics(fixture);
    const name = fixture.slice(fixture.lastIndexOf("/") + 1);
    assert.ok(diagnostics.some((d) => d.includes(name) && d.includes(needle)), diagnostics.join("\n"));
    assert.ok(diagnostics.every((d) => d.includes(name)), `only the fixture is diagnosed:\n${diagnostics.join("\n")}`);
  });
}

// ---- bundle guard: esbuild for the browser, the backend check, then the unresolved-globals scan ----

interface Guard {
  bundleForBrowser(options: { entry?: string; stdin?: string }): Promise<{ ok: true; code: string; bytes: number; metafile: { inputs: Record<string, unknown> } } | { ok: false; errors: string[] }>;
  scanUnresolvedGlobals(code: string): Promise<string[]>;
  backendFindings(inputs: string[]): string[];
}
const guard = async (): Promise<Guard> => (await import(pathToFileURL(join(REPO, "tools/browser-guard.mjs")).href)) as Guard;

test("bundle guard red-proof: an entry that imports node:crypto fails the browser build", async () => {
  const result = await (await guard()).bundleForBrowser({ stdin: 'export { createHash } from "node:crypto";' });
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors.some((e) => e.includes("node:crypto")), result.errors.join("\n"));
});

test("bundle guard red-proof: a bundle with a free Buffer (and a free process) reference is caught by no-undef", async () => {
  const found = await (await guard()).scanUnresolvedGlobals('var a = Buffer.from("x"); var b = process.env; var ok = new TextEncoder();');
  assert.deepEqual(found.sort(), ["Buffer", "process"]);
});

test("bundle guard red-proof: the cast plant (globalThis as unknown as {...}).Buffer.from(...) is caught once the cast is erased", async () => {
  const plant = 'export const p = (globalThis as unknown as { Buffer: { from(s: string): Uint8Array } }).Buffer.from("x");\n' +
    'export const q = (self as unknown as { process: { env: unknown } }).process.env;\n' +
    'export const r = (window as unknown as { require(s: string): unknown }).require("x");';
  const { code } = await transform(plant, { loader: "ts", format: "esm", target: "es2022" });
  assert.ok(code.includes("globalThis.Buffer.from"), code);
  const found = await (await guard()).scanUnresolvedGlobals(code);
  for (const access of ["globalThis.Buffer", "self.process", "window.require"]) {
    assert.ok(found.some((f) => f.includes(access)), `${access} must be a finding:\n${found.join("\n")}`);
  }
});

test("bundle guard red-proof: eval and new Function in a bundle are caught", async () => {
  const found = await (await guard()).scanUnresolvedGlobals('var a = eval("1"); var f = new Function("return 1");');
  assert.ok(found.some((f) => f.includes("eval")) && found.some((f) => f.includes("Function")), found.join("\n"));
});

test("bundle guard red-proof: a bundle reaching the verifier's node backend, or missing its portable one, is a finding", async () => {
  const { backendFindings } = await guard();
  assert.deepEqual(backendFindings(["x/dist/src/index.js", "verifier/dist/src/crypto/portable.js"]), []);
  assert.equal(backendFindings(["verifier/dist/src/crypto/node.js", "verifier/dist/src/crypto/portable.js"]).length, 1);
  assert.equal(backendFindings(["x/dist/src/index.js"]).length, 1);
});

test("bundle guard: the signer's source entry bundles for the browser through the verifier's portable backend", async () => {
  // The published entry is checked by `pnpm guard:browser` after `pnpm build`; here the same layers
  // run over the TypeScript source so the unit suite needs no build.
  const g = await guard();
  const source = await g.bundleForBrowser({ entry: join(REPO, "src/index.ts") });
  assert.equal(source.ok, true, source.ok ? "" : source.errors.join("\n"));
  if (!source.ok) return;
  assert.deepEqual(g.backendFindings(Object.keys(source.metafile.inputs)), []);
  assert.deepEqual(await g.scanUnresolvedGlobals(source.code), []);
});
