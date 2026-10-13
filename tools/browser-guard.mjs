#!/usr/bin/env node
// The browser-bundle guard (pnpm guard:browser, after pnpm build). Two layers over the PUBLISHED entry
// (dist/src/index.js) and its verifier dependency, as a browser bundler sees them:
//   1. esbuild with platform "browser": an import of any Node built-in that is not resolvable for the
//      browser fails the build, and the metafile must name the verifier's portable backend and never
//      its node backend or node:crypto.
//   2. a scope-aware unresolved-globals scan of the bundled output: ESLint no-undef with the ES2022 and
//      browser globals only, so a free Buffer, process, require or __dirname reference anywhere in the
//      bundle (ours or a dependency's) is a finding; eval, implied eval and the Function constructor
//      are findings too (the strict CSP in the browser lane forbids them).
// test/guards.test.ts red-proofs both layers through the exported functions. With --scan <file> it runs
// the second layer alone over an already-built bundle (the Pages playground, site-dist/app.js).
import { build } from "esbuild";
import { Linter } from "eslint";
import globals from "globals";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

export async function bundleForBrowser({ entry, stdin, minify = false }) {
  try {
    const result = await build({
      ...(stdin === undefined
        ? { entryPoints: [entry ?? join(ROOT, "dist/src/index.js")] }
        : { stdin: { contents: stdin, resolveDir: ROOT, sourcefile: "guard-entry.js", loader: "js" } }),
      absWorkingDir: ROOT,
      bundle: true,
      write: false,
      format: "esm",
      platform: "browser",
      target: "es2022",
      minify,
      metafile: true,
      logLevel: "silent",
    });
    const code = result.outputFiles[0].text;
    return { ok: true, code, bytes: result.outputFiles[0].contents.length, metafile: result.metafile };
  } catch (e) {
    const errors = (e.errors ?? [{ text: String(e) }]).map((x) => `${x.text}${x.location ? ` (${x.location.file}:${x.location.line})` : ""}`);
    return { ok: false, errors };
  }
}

const SCAN_CONFIG = [
  {
    languageOptions: { ecmaVersion: 2022, sourceType: "module", globals: { ...globals.es2022, ...globals.browser } },
    rules: { "no-undef": "error", "no-eval": "error", "no-implied-eval": "error", "no-new-func": "error" },
  },
];

// Returns the free (unresolved) global names, and "rule: message" for dynamic-code findings.
export async function scanUnresolvedGlobals(code) {
  const messages = new Linter({ configType: "flat" }).verify(code, SCAN_CONFIG);
  const out = new Set();
  for (const m of messages) {
    if (m.fatal) out.add(`parse: ${m.message}`);
    else if (m.ruleId === "no-undef") out.add(/'([^']+)' is not defined/.exec(m.message)?.[1] ?? m.message);
    else out.add(`${m.ruleId}: ${m.message}`);
  }
  return [...out];
}

// The metafile inputs that a browser bundle must never contain, and the one it must.
export function backendFindings(inputs) {
  const findings = inputs
    .filter((p) => /src\/crypto\/node\.js$/.test(p) || /^node:|^(crypto|buffer)$/.test(p))
    .map((p) => `the browser bundle reaches a Node-only input: ${p}`);
  if (!inputs.some((p) => /src\/crypto\/portable\.js$/.test(p))) findings.push("the browser bundle does not contain the verifier's portable backend");
  return findings;
}

async function scanFile(file) {
  const { readFileSync } = await import("node:fs");
  const findings = await scanUnresolvedGlobals(readFileSync(file, "utf8"));
  if (findings.length > 0) {
    console.error(`browser-guard: ${findings.length} finding(s) in ${file}:`);
    for (const f of findings) console.error(`  ${f}`);
    process.exit(1);
  }
  console.log(`browser-guard: PASS (${file}: no unresolved globals, eval or Function constructor)`);
}

async function main() {
  const scan = process.argv.indexOf("--scan");
  if (scan !== -1) return scanFile(process.argv[scan + 1]);
  const result = await bundleForBrowser({});
  if (!result.ok) {
    console.error("browser-guard: the browser build of dist/src/index.js failed:");
    for (const e of result.errors) console.error(`  ${e}`);
    process.exit(1);
  }
  const inputs = Object.keys(result.metafile.inputs);
  const problems = [...backendFindings(inputs), ...(await scanUnresolvedGlobals(result.code))];
  if (problems.length > 0) {
    console.error(`browser-guard: ${problems.length} finding(s) in the browser bundle:`);
    for (const f of problems) console.error(`  ${f}`);
    process.exit(1);
  }
  console.log(`browser-guard: PASS (${inputs.length} modules, ${result.bytes} bytes unminified; the verifier's portable backend only; no unresolved globals, eval or Function constructor)`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) await main();
