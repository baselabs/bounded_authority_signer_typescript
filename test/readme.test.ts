// The README's TypeScript samples, typechecked and run against this source (no mocks: real keys, the
// real verifier package). The markers are described in test/readme-samples.ts. The package specifier is
// rewritten to this repository's src/index.js, so the samples run against the code at HEAD; under
// test:portable they run on the verifier's portable backend. test/reader.ts runs the Quickstart the way a
// reader does instead: an empty directory, the README's setup commands, the published packages.
// The types samples must be the exported declarations, text for text; the last test checks that every
// README anchor that the README itself or a src/ doc comment links to exists.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { format } from "node:util";
import ts from "typescript";
import { parse } from "./readme-samples.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const SRC_INDEX = join(REPO, "src/index.js");
const PACKAGE = "@bounded-authority-protocol/signer";
const README = readFileSync(join(REPO, "README.md"), "utf8");

const SAMPLES = parse(README).filter((s) => s.kind !== "setup");
let dir = "";

function typecheck(baseConfig: string, files: readonly string[]): string[] {
  const config = join(dir, `tsconfig.${baseConfig.replace(/\W/g, "_")}.json`);
  writeFileSync(config, JSON.stringify({ extends: join(REPO, baseConfig), compilerOptions: { noEmit: true }, include: [], files }));
  const parsed = ts.getParsedCommandLineOfConfigFile(config, {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} });
  assert.ok(parsed, "the config parses");
  const program = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options });
  return ts.getPreEmitDiagnostics(program).map((d) => {
    const where = d.file ? `${d.file.fileName.replace(dir, "")}:${d.file.getLineAndCharacterOfPosition(d.start ?? 0).line + 1}` : "";
    return `${where} TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`;
  });
}

before(() => {
  mkdirSync(join(REPO, "node_modules/.cache"), { recursive: true });
  dir = mkdtempSync(join(REPO, "node_modules/.cache/bap-readme-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ type: "module" }));
  for (const sample of SAMPLES) {
    let code = sample.code.replaceAll(`"${PACKAGE}"`, JSON.stringify(SRC_INDEX));
    if (sample.kind === "types") {
      // Each declared name must be the same type as the package export of that name.
      const names = [...sample.code.matchAll(/^(?:export\s+)?(?:interface|type)\s+(\w+)/gm)].map((m) => m[1]!);
      assert.ok(names.length > 0, `README.md:${sample.line}: a types sample declares at least one type`);
      code += `\nimport type * as __Package from ${JSON.stringify(SRC_INDEX)};\n` +
        "type __Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;\n" +
        names.map((n) => `export const __same_${n}: __Same<${n}, __Package.${n}> = true;`).join("\n") + "\n";
    }
    writeFileSync(join(dir, sample.fileName), code);
  }
});

after(() => {
  if (dir !== "") rmSync(dir, { recursive: true, force: true });
});

test("README: the samples are found, and every runnable one has a recorded output or prints nothing checked", () => {
  assert.ok(SAMPLES.filter((s) => s.kind === "run").length >= 5, `found ${SAMPLES.length} samples`);
  assert.ok(SAMPLES.some((s) => s.kind === "run-dom"));
  assert.ok(SAMPLES.some((s) => s.kind === "types"));
  assert.ok(SAMPLES.some((s) => s.kind === "file" && s.fileName === "key-handle.ts"));
});

test("README: the Node samples, the shared key-handle module and the type shapes typecheck under tsconfig.json", () => {
  const files = SAMPLES.filter((s) => s.kind !== "run-dom").map((s) => join(dir, s.fileName));
  assert.deepEqual(typecheck("tsconfig.json", files), []);
});

test("README: the browser samples typecheck under tsconfig.browser.json (DOM library, no Node types)", () => {
  const files = SAMPLES.filter((s) => s.kind === "run-dom").map((s) => join(dir, s.fileName));
  assert.deepEqual(typecheck("tsconfig.browser.json", files), []);
});

for (const sample of SAMPLES.filter((s) => s.kind === "run" || s.kind === "run-dom")) {
  test(`README.md:${sample.line}: the sample runs${sample.output === undefined ? "" : " and prints the output shown"}`, async () => {
    const printed: string[] = [];
    const log = console.log;
    console.log = (...args: unknown[]) => { printed.push(format(...args)); };
    try {
      await import(pathToFileURL(join(dir, sample.fileName)).href);
    } finally {
      console.log = log;
    }
    if (sample.output !== undefined) assert.equal(printed.join("\n"), sample.output);
  });
}

// The text of a declaration without comments, `export`, or whitespace differences.
const normalized = (text: string): string =>
  text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "").replace(/^\s*export\s+/, "").replace(/\s+/g, " ").replace(/\s*([;{}()<>|:,?=\[\]])\s*/g, "$1").trim();

/** The source text of every type the package root exports, by exported name. */
function exportedDeclarations(): Map<string, string> {
  const index = join(REPO, "src/index.ts");
  const program = ts.createProgram({ rootNames: [index], options: { strict: true, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, noEmit: true } });
  const checker = program.getTypeChecker();
  const moduleSymbol = checker.getSymbolAtLocation(program.getSourceFile(index)!)!;
  const found = new Map<string, string>();
  for (const symbol of checker.getExportsOfModule(moduleSymbol)) {
    const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
    const decl = target.declarations?.find((d) => ts.isInterfaceDeclaration(d) || ts.isTypeAliasDeclaration(d));
    if (decl !== undefined) found.set(symbol.getName(), decl.getText());
  }
  return found;
}

test("README: every declaration in a types sample is the exported declaration, text for text (comments aside)", () => {
  const source = exportedDeclarations();
  let compared = 0;
  for (const sample of SAMPLES.filter((s) => s.kind === "types")) {
    const file = ts.createSourceFile("sample.ts", sample.code, ts.ScriptTarget.ES2022, true);
    for (const statement of file.statements) {
      if (ts.isImportDeclaration(statement)) continue;
      assert.ok(ts.isInterfaceDeclaration(statement) || ts.isTypeAliasDeclaration(statement), `README.md:${sample.line}: a types sample holds only imports and type declarations`);
      const name = statement.name.text;
      const exported = source.get(name);
      assert.ok(exported !== undefined, `README.md:${sample.line}: ${name} is not an exported type`);
      assert.equal(normalized(statement.getText()), normalized(exported), `README.md:${sample.line}: ${name} differs from its source declaration`);
      compared++;
    }
  }
  assert.ok(compared >= 7, `compared ${compared} declarations`);
});

test("README: V2SelectorInput and V2OperationInput declare the same members as their v3 counterparts, as the README says", () => {
  const source = exportedDeclarations();
  const body = (name: string): string => normalized(source.get(name)!).replace(/^(type|interface)\s*\w+/, "").replaceAll("V2SelectorInput", "V3SelectorInput");
  assert.equal(body("V2SelectorInput"), body("V3SelectorInput"));
  assert.equal(body("V2OperationInput"), body("V3OperationInput"));
});

// GitHub's heading anchors: lowercase, punctuation other than hyphens and spaces dropped, spaces to hyphens.
function anchors(markdown: string): Set<string> {
  const found = new Set<string>();
  let inFence = false;
  for (const line of markdown.split("\n")) {
    if (line.startsWith("```")) inFence = !inFence;
    const heading = inFence ? null : /^#{1,6}\s+(.*)$/.exec(line);
    if (heading === null) continue;
    found.add(heading[1]!.trim().toLowerCase().replace(/`/g, "").replace(/[^\p{L}\p{N}\s-]/gu, "").replace(/\s/g, "-"));
  }
  return found;
}

test("README: every anchor linked from the README and from src/ doc comments exists", () => {
  const known = anchors(README);
  const wanted = new Map<string, string>();
  for (const m of README.matchAll(/\]\(#([^)]+)\)/g)) wanted.set(m[1]!, "README.md");
  for (const name of readdirSync(join(REPO, "src")).filter((f) => f.endsWith(".ts"))) {
    const source = readFileSync(join(REPO, "src", name), "utf8");
    for (const m of source.matchAll(/bounded_authority_signer_typescript#([a-z0-9-]+)/g)) wanted.set(m[1]!, `src/${name}`);
  }
  assert.ok(wanted.size > 5);
  for (const [anchor, from] of wanted) assert.ok(known.has(anchor), `${from} links to #${anchor}, which is not a README heading`);
});
