// The README's TypeScript samples, typechecked and run against this source (no mocks: real keys, the
// real verifier package). Each code fence in README.md that a reader would copy carries a marker on the
// line before it:
//
//   <!-- readme-sample: file NAME -->  a module the other samples import (typechecked with them)
//   <!-- readme-sample: run -->        typechecked under tsconfig.json (Node types), then run
//   <!-- readme-sample: run-dom -->    typechecked under tsconfig.browser.json (DOM library, no Node types), then run
//   <!-- readme-sample: types -->      typechecked; every interface or type it declares must be mutually
//                                      assignable with the package export of the same name
//   <!-- readme-output -->             before a text fence: the exact console output of the run sample above it
//
// A ts/typescript/js fence without a marker fails the test. The package specifier is rewritten to this
// repository's src/index.js, so the samples run against the code at HEAD; under test:portable they run on
// the verifier's portable backend. The last test checks that every README anchor that the README itself
// or a src/ doc comment links to exists.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { format } from "node:util";
import ts from "typescript";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const SRC_INDEX = join(REPO, "src/index.js");
const PACKAGE = "@bounded-authority-protocol/signer";
const README = readFileSync(join(REPO, "README.md"), "utf8");

type Kind = "file" | "run" | "run-dom" | "types";
interface Sample {
  readonly kind: Kind;
  readonly line: number;      // 1-based line of the opening fence
  readonly code: string;
  readonly fileName: string;
  output?: string;
}

function parse(markdown: string): Sample[] {
  const lines = markdown.split("\n");
  const samples: Sample[] = [];
  let index = 0;
  for (let i = 0; i < lines.length; i++) {
    const fence = /^```(\w*)/.exec(lines[i]!);
    if (fence === null) continue;
    const lang = fence[1]!;
    let end = i + 1;
    while (end < lines.length && lines[end] !== "```") end++;
    assert.ok(end < lines.length, `README.md:${i + 1}: unclosed fence`);
    const body = lines.slice(i + 1, end).join("\n");
    const marker = i > 0 ? lines[i - 1]! : "";
    if (marker === "<!-- readme-output -->") {
      assert.equal(lang, "text", `README.md:${i + 1}: an output block is a text fence`);
      const owner = samples.at(-1);
      assert.ok(owner !== undefined && (owner.kind === "run" || owner.kind === "run-dom") && owner.output === undefined,
        `README.md:${i + 1}: an output block must follow a run sample that has no output block yet`);
      owner.output = body;
    } else if (["ts", "typescript", "js", "javascript", "tsx", "mjs"].includes(lang)) {
      const m = /^<!-- readme-sample: (file ([\w.-]+\.ts)|run|run-dom|types) -->$/.exec(marker);
      assert.ok(m !== null, `README.md:${i + 1}: a ${lang} fence needs a readme-sample marker on the line before it`);
      const kind = (m[2] === undefined ? m[1] : "file") as Kind;
      samples.push({ kind, line: i + 1, code: body, fileName: m[2] ?? `sample-${String(++index).padStart(2, "0")}-line-${i + 1}.ts` });
    }
    i = end;
  }
  return samples;
}

const SAMPLES = parse(README);
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
