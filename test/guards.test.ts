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

// ---- T14: the WebCrypto key-handle file (src/webcrypto.ts, signer 0.6.0; design §12.6, revision R4) ----
//
// src/webcrypto.ts is the one file allowed to reach crypto.subtle, and only as two DIRECT calls:
// subtle.sign(...) and subtle.exportKey("raw", ...) with the literal "raw". Its override is built from the
// same shared rule arrays as the rest of src/, minus exactly the subtle and exportKey allowances, so every
// base ban must still fire inside it. Each new ban has a probe in both files, and a red-proof that lints
// the probe again under a config with the entries that caught it removed: the probe must then pass.

const WEBCRYPTO_FILE = "src/webcrypto.ts";
const ALLOWED_ONLY_IN_WEBCRYPTO = new Set(["crypto.subtle", "globalThis.crypto.subtle"]);

for (const [label, code, rule] of LINT_PROBES) {
  if (ALLOWED_ONLY_IN_WEBCRYPTO.has(label)) {
    test(`T14 lint: ${label} is allowed in ${WEBCRYPTO_FILE} only`, async () => {
      assert.deepEqual(await lintRules(code, WEBCRYPTO_FILE), []);
      assert.ok((await lintRules(code, "src/guard-probe.ts")).includes(rule));
    });
    continue;
  }
  // .exportKey moves from the property ban to the direct-call-with-"raw" syntax rule in that one file.
  const expected = label === ".exportKey" ? "no-restricted-syntax" : rule;
  test(`T14 lint: the base ban still fires in ${WEBCRYPTO_FILE}: ${label} (${expected})`, async () => {
    assert.ok((await lintRules(code, WEBCRYPTO_FILE)).includes(expected), `${label} must trip ${expected} in ${WEBCRYPTO_FILE}`);
  });
}

const S = "globalThis.crypto.subtle";
const WEBCRYPTO_PROBES: ReadonlyArray<readonly [string, string]> = [
  ["generateKey", `export const p = ${S}.generateKey({ name: "Ed25519" }, false, ["sign"]);`],
  ["importKey", `export const p = (k: Uint8Array) => ${S}.importKey("raw", k, { name: "Ed25519" }, false, ["verify"]);`],
  ["deriveKey", `export const p = (a: object, k: never) => ${S}.deriveKey(a, k, a, false, []);`],
  ["deriveBits", `export const p = (a: object, k: never) => ${S}.deriveBits(a, k, 256);`],
  ["wrapKey", `export const p = (k: never, w: never) => ${S}.wrapKey("raw", k, w, "AES-KW");`],
  ["unwrapKey", `export const p = (w: never) => ${S}.unwrapKey("raw", new Uint8Array(1), w, "AES-KW", "AES-GCM", false, []);`],
  ["encrypt", `export const p = (k: never) => ${S}.encrypt({ name: "AES-GCM" }, k, new Uint8Array(1));`],
  ["decrypt", `export const p = (k: never) => ${S}.decrypt({ name: "AES-GCM" }, k, new Uint8Array(1));`],
  ["digest", `export const p = ${S}.digest("SHA-256", new Uint8Array(1));`],
  ['exportKey("pkcs8")', `export const p = (k: never) => ${S}.exportKey("pkcs8", k);`],
  ['exportKey("jwk")', `export const p = (k: never) => ${S}.exportKey("jwk", k);`],
  ['exportKey("spki")', `export const p = (k: never) => ${S}.exportKey("spki", k);`],
  ["exportKey(non-literal format)", `export const p = (f: "raw", k: never) => ${S}.exportKey(f, k);`],
  ["exportKey(`raw`) (template, not the literal)", `export const p = (k: never) => ${S}.exportKey(\`raw\`, k);`],
  ["exportKey not called directly", `export const p = ${S}.exportKey;`],
  ["exportKey via .call", `export const p = (k: never) => ${S}.exportKey.call(${S}, "raw", k);`],
  ['exportKey by string key', `export const p = (k: never) => ${S}["exportKey"]("raw", k);`],
  ["exportKey destructured", `const { exportKey } = ${S};\nexport const p = exportKey;`],
  ["sign not called directly", `export const p = ${S}.sign;`],
  ["sign via .call", `export const p = (k: never, m: Uint8Array) => ${S}.sign.call(${S}, { name: "Ed25519" }, k, m);`],
  ["sign via .apply", `export const p = (k: never, m: Uint8Array) => ${S}.sign.apply(${S}, [{ name: "Ed25519" }, k, m]);`],
  ["sign via .bind", `export const p = ${S}.sign.bind(${S});`],
  ["sign by string key", `export const p = (k: never, m: Uint8Array) => ${S}["sign"]({ name: "Ed25519" }, k, m);`],
  ["sign destructured", `const { sign } = ${S};\nexport const p = sign;`],
  ["sign through Reflect.get", `export const p = Reflect.get(${S}, "sign");`],
  ["subtle destructured", `const { subtle } = globalThis.crypto;\nexport const p = subtle;`],
  // F6: names assembled at run time.
  ["computed member with a concatenated name", `export const p = (o: Record<string, unknown>) => o["ex" + "portKey"];`],
  ["computed member with a template that has expressions", `const a = "ex";\nexport const p = (o: Record<string, unknown>) => o[\`\${a}portKey\`];`],
  ["String.fromCharCode", `export const p = String.fromCharCode(115, 105, 103, 110);`],
  ["String.fromCodePoint", `export const p = String.fromCodePoint(115, 105, 103, 110);`],
  // F3: method lookup by string and the captured exportKey called through Reflect.apply.
  ["a key-material name as a string (getOwnPropertyDescriptor)", `export const p = (o: object) => Object.getOwnPropertyDescriptor(o, "generateKey");`],
  ['captured exportKey through reflectApply with "pkcs8"', `declare const reflectApply: typeof Reflect.apply;\ndeclare const SUBTLE_EXPORT_KEY: () => unknown;\ndeclare const SUBTLE: object;\nexport const p = (k: unknown) => reflectApply(SUBTLE_EXPORT_KEY, SUBTLE, ["pkcs8", k]);`],
  ["captured exportKey through reflectApply with a non-literal format", `declare const reflectApply: typeof Reflect.apply;\ndeclare const SUBTLE_EXPORT_KEY: () => unknown;\ndeclare const SUBTLE: object;\nexport const p = (f: string, k: unknown) => reflectApply(SUBTLE_EXPORT_KEY, SUBTLE, [f, k]);`],
];

interface FlatBlock { files?: string[]; rules?: Record<string, unknown> }
const realConfig = async (): Promise<FlatBlock[]> => (await import(pathToFileURL(join(REPO, "eslint.config.js")).href)).default as FlatBlock[];

async function lintMessages(code: string, filePath: string, config?: FlatBlock[]): Promise<{ ruleId: string; message: string }[]> {
  const engine = config === undefined ? eslint : new ESLint({ cwd: REPO, overrideConfigFile: true, overrideConfig: config as never });
  const [result] = await engine.lintText(code, { filePath: join(REPO, filePath) });
  return (result?.messages ?? []).map((m) => ({ ruleId: m.ruleId ?? `fatal: ${m.message}`, message: m.message }));
}

// The real config with every restricted-syntax/-properties entry whose message was reported removed.
function withoutEntries(config: FlatBlock[], reported: string[]): FlatBlock[] {
  return config.map((block) => {
    if (!block.rules) return block;
    const rules = { ...block.rules };
    for (const name of ["no-restricted-syntax", "no-restricted-properties"]) {
      const value = rules[name];
      if (!Array.isArray(value)) continue;
      const [severity, ...entries] = value as [unknown, ...{ message?: string }[]];
      rules[name] = [severity, ...entries.filter((e) => !reported.some((m) => e.message !== undefined && m.includes(e.message)))];
    }
    return { ...block, rules };
  });
}

for (const [label, code] of WEBCRYPTO_PROBES) {
  for (const file of [WEBCRYPTO_FILE, "src/guard-probe.ts"]) {
    test(`T14 lint probe: ${label} is refused in ${file}, and passes once the entries that caught it are removed (red-proof)`, async () => {
      const found = await lintMessages(code, file);
      const restricted = found.filter((m) => m.ruleId === "no-restricted-syntax" || m.ruleId === "no-restricted-properties");
      assert.ok(restricted.length > 0, `${label} must be refused in ${file}: ${JSON.stringify(found)}`);
      const relaxed = await lintMessages(code, file, withoutEntries(await realConfig(), restricted.map((m) => m.message)));
      assert.deepEqual(relaxed.filter((m) => m.ruleId === "no-restricted-syntax" || m.ruleId === "no-restricted-properties"), [], `${label}: with its rule entries removed the probe passes`);
    });
  }
}

test("T14 lint (F3): capturing SubtleCrypto.prototype.sign and exportKey by descriptor, and the raw export through reflectApply, are allowed in src/webcrypto.ts only", async () => {
  const code = [
    "declare const reflectApply: typeof Reflect.apply;",
    "const proto = Object.getPrototypeOf(globalThis.crypto.subtle) as object;",
    'export const SUBTLE_SIGN = Object.getOwnPropertyDescriptor(proto, "sign")?.value as () => unknown;',
    'export const SUBTLE_EXPORT_KEY = Object.getOwnPropertyDescriptor(proto, "exportKey")?.value as () => unknown;',
    'export const raw = (k: unknown) => reflectApply(SUBTLE_EXPORT_KEY, proto, ["raw", k]);',
  ].join("\n");
  assert.deepEqual(await lintRules(code, WEBCRYPTO_FILE), []);
  const outside = await lintMessages(code, "src/guard-probe.ts");
  assert.ok(outside.filter((m) => /^the strings /.test(m.message)).length === 2, JSON.stringify(outside));
});

test("T14 lint: the two direct calls and the CryptoKey.prototype getter reads are allowed in src/webcrypto.ts", async () => {
  const code = [
    "const s = globalThis.crypto.subtle;",
    'export const raw = (k: never) => s.exportKey("raw", k);',
    'export const sig = (k: never, m: Uint8Array) => s.sign({ name: "Ed25519" }, k, m);',
    'export const get = Object.getOwnPropertyDescriptor(CryptoKey.prototype, "extractable")?.get;',
  ].join("\n");
  assert.deepEqual(await lintRules(code, WEBCRYPTO_FILE), []);
  assert.ok((await lintRules(code, "src/guard-probe.ts")).includes("no-restricted-syntax"), "outside src/webcrypto.ts the same code is refused");
});

test("T14 lint: the src/webcrypto.ts override is built from the shared arrays (every base entry is present there)", async () => {
  const config = await realConfig();
  const base = config.find((b) => b.files?.includes("src/**/*.ts"))!.rules!;
  const override = config.find((b) => b.files?.includes(WEBCRYPTO_FILE))!.rules!;
  const messages = (rule: string, rules: Record<string, unknown>) => ((rules[rule] as { message?: string }[] | undefined) ?? []).slice(1).map((e) => e.message);
  const allowed = (m: string | undefined) => /crypto\.subtle\) is forbidden|\.exportKey is a key-generation|^the strings /.test(m ?? "");
  for (const rule of ["no-restricted-syntax", "no-restricted-properties"]) {
    const missing = messages(rule, base).filter((m) => !allowed(m) && !messages(rule, override).includes(m));
    assert.deepEqual(missing, [], `${rule}: base entries missing from the override`);
  }
  assert.equal(messages("no-restricted-syntax", base).filter(allowed).length, 2, "exactly two base syntax entries are relaxed: the subtle member ban, and the string ban (narrowed, not dropped)");
  assert.ok(messages("no-restricted-syntax", override).some((m) => /^in src\/webcrypto\.ts the strings /.test(m ?? "")), "the narrowed string ban is present in the override");
  assert.equal(messages("no-restricted-properties", base).filter(allowed).length, 1, "exactly one base property entry (.exportKey) is relaxed");
});

// ---- T14: the dist/ scan (tools/browser-guard.mjs keyMaterialFindings, run by pnpm guard:browser) ----

interface KeyScan { keyMaterialFindings(files: { path: string; code: string }[]): Promise<string[]> }
const keyScan = async (): Promise<KeyScan> => (await import(pathToFileURL(join(REPO, "tools/browser-guard.mjs")).href)) as KeyScan;

test("T14 dist scan red-proof: pkcs8, spki, a banned key-material name, jwk in webcrypto.js and exportKey outside it are findings", async () => {
  const { keyMaterialFindings } = await keyScan();
  const plant = (path: string, code: string) => keyMaterialFindings([{ path, code }]);
  assert.ok((await plant("dist/src/webcrypto.js", 'export const p = (s, k) => s.exportKey("pkcs8", k);')).some((f) => f.includes("pkcs8")));
  assert.ok((await plant("dist/src/webcrypto.js", "export const p = (s, k) => s.exportKey(`spki`, k);")).some((f) => f.includes("spki")));
  assert.ok((await plant("dist/src/webcrypto.js", 'export const p = (s, k) => s.exportKey("jwk", k);')).some((f) => f.includes("jwk")));
  for (const name of ["generateKey", "importKey", "deriveKey", "deriveBits", "wrapKey", "unwrapKey", "encrypt", "decrypt", "digest", "keygen", "getPublicKey", "getSharedSecret", "randomSecretKey"]) {
    assert.ok((await plant("dist/src/api.js", `export const p = (s) => s.${name}();`)).some((f) => f.includes(name)), name);
    assert.ok((await plant("dist/src/api.js", `export const p = (s) => s["${name}"]();`)).some((f) => f.includes(name)), `${name} by string key`);
  }
  assert.ok((await plant("dist/src/api.js", 'export const p = (s, k) => s.exportKey("raw", k);')).some((f) => f.includes("exportKey")));
  assert.deepEqual(await plant("dist/src/v3.js", 'export const h = { jwk: 1, "jwk": 2 }; // pkcs8 in a comment is not code'), [], "jwk outside webcrypto.js (the DPoP header member) and comments are not findings");
  assert.deepEqual(await plant("dist/src/webcrypto.js", 'export const p = (s, k) => s.exportKey("raw", k);'), []);
});

test("T14 dist scan: the src/ files, transpiled as tsc emits them into dist/src, have no finding", async () => {
  const { readdirSync, readFileSync: read } = await import("node:fs");
  const files = [];
  for (const name of readdirSync(join(REPO, "src")).filter((f) => f.endsWith(".ts"))) {
    const { code } = await transform(read(join(REPO, "src", name), "utf8"), { loader: "ts", format: "esm", target: "es2022" });
    files.push({ path: `dist/src/${name.replace(/\.ts$/, ".js")}`, code });
  }
  assert.ok(files.some((f) => f.path === "dist/src/webcrypto.js"), "src/webcrypto.ts is scanned");
  assert.deepEqual(await (await keyScan()).keyMaterialFindings(files), []);
});

test("bundle guard (design §12.6): crypto and CryptoKey are browser globals for the scan (src/webcrypto.ts reads both)", async () => {
  const g = await guard();
  assert.deepEqual(await g.scanUnresolvedGlobals("var s = crypto.subtle; var p = CryptoKey.prototype; var r = Reflect.apply;"), []);
  assert.deepEqual(await g.scanUnresolvedGlobals("var s = cryptoo.subtle;"), ["cryptoo"], "a misspelled global is still a finding (the scan is not vacuous)");
});
