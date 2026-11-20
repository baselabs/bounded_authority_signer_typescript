import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { anchors, discover, files, links, parse } from "../tools/documentation.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (file: string): string => readFileSync(join(root, file), "utf8");
const pkg = JSON.parse(read("package.json")) as { name: string; version: string; dependencies: Record<string, string> };
const surfaces = files(root).filter((f) => f.endsWith(".md") || f.endsWith(".ipynb") || f.startsWith("web/") && f.endsWith(".html"));
const samples = discover(root);

test("README renders whole and retains orientation, trust, install, quickstart and guide index", () => {
  const readme = read("README.md");
  assert.ok(Buffer.byteLength(readme, "utf8") < 32_768, "README must remain well below npm's 65,536 character truncation");
  const ids = anchors(readme);
  for (const id of ["when-to-use-it", "when-not-to-use-it", "trust-boundary", "install", "quickstart", "documentation", "notebooks", "security", "development", "license"]) assert.ok(ids.has(id), id);
});

test("CommonMark discovery includes indented, nested and tilde fences; missing outputs fail", () => {
  const nested = "> <!-- readme-sample: run -->\n> ~~~~typescript\n> console.log('ok');\n> ~~~~\n> <!-- readme-output -->\n> ~~~~text\n> ok\n> ~~~~\n";
  assert.equal(parse(nested)[0]?.output, "ok");
  const indented = "   <!-- readme-sample: run -->\n   ```ts\n   console.log('ok');\n   ```\n   <!-- readme-output -->\n   ```text\n   ok\n   ```\n";
  assert.equal(parse(indented)[0]?.output, "ok");
  assert.throws(() => parse("```ts\nconsole.log('missed');\n```"), /marker/);
  assert.throws(() => parse("<!-- readme-sample: run -->\n```ts\nconsole.log('missed');\n```"), /recorded output/);
  assert.ok(samples.some((s) => s.source.startsWith("docs/guides/")));
  assert.ok(samples.some((s) => s.source.startsWith("src/")));
  assert.ok(samples.some((s) => s.source.startsWith("web/")));
  assert.ok(samples.some((s) => s.kind === "notebook"));
});

test("every relative document link and fragment resolves, including notebook Markdown", () => {
  for (const file of surfaces) {
    const text = file.endsWith(".ipynb") ? (JSON.parse(read(file)) as { cells: { cell_type: string; source: string[] }[] }).cells
      .filter((c) => c.cell_type === "markdown").map((c) => c.source.join("")).join("\n") : read(file);
    for (const href of links(text)) {
      if (/^(?:[a-z]+:|\/\/)/i.test(href)) continue;
      const [path = "", fragment] = decodeURIComponent(href).split("#");
      const target = path ? resolve(root, dirname(file), path.split("?")[0]!) : join(root, file);
      // The source page names two generated build outputs. Require the producing contract
      // here; the real-engine test requests the generated assets and site entry point.
      if (file === "web/index.html" && ["./api/", "./app.js"].includes(path.split("?")[0]!)) {
        const scripts = JSON.parse(read("package.json")) as { scripts: Record<string, string> };
        if (path === "./api/") assert.equal(JSON.parse(read("typedoc.json")).out, "site-dist/api");
        else assert.ok(scripts.scripts["build:site"]?.includes("--outfile=site-dist/app.js"));
        continue;
      }
      assert.ok(existsSync(target), `${file}: ${href} missing`);
      if (fragment && /\.(?:md|html)$/.test(target)) assert.ok(anchors(readFileSync(target, "utf8")).has(fragment), `${file}: ${href} missing anchor`);
    }
  }
});

test("pins on current install surfaces match package.json; the error table exactly covers the source union", () => {
  for (const file of surfaces.filter((f) => f !== "CHANGELOG.md" && !f.endsWith("upgrading.md"))) {
    for (const m of read(file).matchAll(/@bounded-authority-protocol\/(signer|verifier)@(\d+\.\d+\.\d+)/g)) assert.equal(m[2], m[1] === "signer" ? pkg.version : pkg.dependencies["@bounded-authority-protocol/verifier"]!.replace(/^[~^]/, ""), `${file}: stale ${m[1]} install`);
  }
  const code = read("src/handle.ts").split("export type SignerErrorCode =")[1]!.split(";")[0]!;
  const codes = [...code.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]).sort();
  const rows = [...read("docs/guides/errors.md").matchAll(/^\| `([a-z_]+)` \|/gm)].map((m) => m[1]).sort();
  assert.deepEqual(rows, codes);
});

test("notebook registry, pinned imports, persisted outputs and generated guide coverage are complete", () => {
  const registry = JSON.parse(read("docs/notebooks/registry.json")) as { schema: number; package: string; version: string; packages: Record<string, string>; notebooks: { file: string; title: string }[] };
  assert.equal(registry.schema, 1); assert.equal(registry.package, pkg.name);
  assert.equal(registry.version, pkg.version); assert.equal(registry.packages[pkg.name], pkg.version);
  const notebookFiles = surfaces.filter((f) => f.endsWith(".ipynb")).map((f) => f.replaceAll("\\", "/")).sort();
  assert.deepEqual(registry.notebooks.map((n) => `docs/notebooks/${n.file}`).sort(), notebookFiles);
  for (const file of notebookFiles) {
    const nb = JSON.parse(read(file)) as { metadata: { kernelspec: { name: string } }; cells: { cell_type: string; source: string[]; outputs?: unknown[] }[] };
    assert.equal(nb.metadata.kernelspec.name, "deno");
    const launch = nb.cells.find((c) => c.cell_type === "markdown")!.source.join("");
    assert.ok(launch.includes("deno jupyter --install"));
    assert.ok(launch.includes("Jupyter"));
    assert.ok(!/uv sync|Python [0-9]|pnpm notebooks/.test(launch), `${file}: contributor setup in launch instructions`);
    const cells = nb.cells.filter((c) => c.cell_type === "code");
    assert.ok(cells.length > 0);
    for (const cell of cells) assert.ok(cell.outputs?.length, `${file}: missing persisted output`);
    assert.ok(cells.some((c) => c.source.join("").includes(`npm:${pkg.name}@${pkg.version}`)));
  }
  const config = JSON.parse(read("typedoc.json")) as { projectDocuments: string[]; validation: Record<string, boolean>; requiredToBeDocumented: string[] };
  for (const file of surfaces.filter((f) => f.startsWith("docs/guides/") && f.endsWith(".md"))) assert.ok(config.projectDocuments.includes(file), `${file}: absent from generated docs`);
  for (const kind of ["Property", "Method", "Function", "Interface", "TypeAlias"]) assert.ok(config.requiredToBeDocumented.includes(kind));
  assert.equal(config.validation.notDocumented, true);
});

test("notebook qualification uses the pinned shared composite action and frozen locks", () => {
  const workflow = read(".github/workflows/ci.yml");
  const action = read(".github/actions/notebook-tools/action.yml");
  assert.equal((workflow.match(/uses: \.\/\.github\/actions\/notebook-tools/g) ?? []).length, 1);
  assert.ok(workflow.includes("notebooks-local") && !workflow.includes("notebooks-published"));
  assert.ok(action.includes("pnpm install --frozen-lockfile"));
  assert.ok(action.includes("uv lock --check") && action.indexOf("uv lock --check") < action.indexOf("uv sync --frozen"));
  assert.ok(action.includes("enable-cache: false") && action.includes("save-cache: false"));
  assert.ok(action.includes("run: scripts/tool-versions.sh read nodejs deno python uv"));
  for (const tool of ["nodejs", "deno", "python", "uv"]) assert.ok(action.includes(`scripts/tool-versions.sh check ${tool}`), tool);
  const scripts = JSON.parse(read("package.json")) as { scripts: Record<string, string> };
  for (const mode of ["local", "published"]) assert.ok(scripts.scripts[`notebooks:${mode}`]?.includes(`scripts/check_notebooks.py --${mode}`));
});

test("public functions and nested API members have docs and real examples, with a task group", () => {
  const index = join(root, "src/index.ts");
  const program = ts.createProgram({ rootNames: [index], options: { module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, noEmit: true } });
  const checker = program.getTypeChecker();
  const exports = checker.getExportsOfModule(checker.getSymbolAtLocation(program.getSourceFile(index)!)!);
  const functions: string[] = [];
  for (const symbol of exports) {
    const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
    assert.ok(ts.displayPartsToString(target.getDocumentationComment(checker)).trim(), symbol.name);
    const checkMembers = (node: ts.Node): void => {
      if (ts.isPropertySignature(node) || ts.isMethodSignature(node)) {
        const member = checker.getSymbolAtLocation(node.name);
        assert.ok(member && ts.displayPartsToString(member.getDocumentationComment(checker)).trim(),
          `${symbol.name}.${node.name.getText()}: member documentation`);
      }
      ts.forEachChild(node, checkMembers);
    };
    for (const declaration of target.getDeclarations() ?? []) if (ts.isInterfaceDeclaration(declaration) || ts.isTypeAliasDeclaration(declaration)) checkMembers(declaration);
    if (target.flags & ts.SymbolFlags.Function) {
      functions.push(symbol.name);
      const tags = target.getJsDocTags(checker);
      assert.ok(tags.some((tag) => tag.name === "example" && ts.displayPartsToString(tag.text).includes("```ts")), `${symbol.name}: example`);
      assert.ok(tags.some((tag) => tag.name === "category"), `${symbol.name}: task category`);
      assert.ok(tags.some((tag) => tag.name === "see"), `${symbol.name}: guide`);
    }
  }
  const guide = read("docs/guides/api-overview.md");
  for (const name of functions) assert.ok(guide.includes(`\`${name}\``), `${name}: API overview`);
  assert.equal(samples.filter((s) => s.source.startsWith("src/") && s.kind === "run-dom").length, functions.length);
});

test("public text excludes em dashes, private design records and internal topology", () => {
  const publicFiles = files(root).filter((f) => /\.(?:md|ipynb|html|css|ts|m?js|ya?ml)$/.test(f) && !f.startsWith("test/"));
  const forbidden = /\bADRs?\b|\bADR[ _-]*\d+\b|\/adr\/|bounded_authority(?:_report_adapter|_protocol)?_private|\/Users\/|devbox-ovh|infra-1/;
  assert.deepEqual(publicFiles.filter((f) => forbidden.test(read(f))), []);

  const dash = String.fromCodePoint(0x2014);
  const emDash = /\u{2014}|\\u(?:2014)/iu;
  // Exact lines and occurrence counts keep the four empty values as data, not prose.
  const emptyValues = new Map<string, string[]>([
    ["web/index.html", [
      `        <div><dt>trusts issuer key</dt><dd><code id="trust-key">${dash}</code></dd></div>`,
      `      <div id="facts-body">${dash}</div>`,
    ]],
    ["web/main.ts", Array<string>(2).fill(`  $("facts-body").textContent = "${dash}";`)],
  ]);
  const findings = (path: string, source: string): string[] => {
    const allowed = [...(emptyValues.get(path) ?? [])];
    return source.split(/\r?\n/).flatMap((line, index) => {
      const allowance = allowed.indexOf(line);
      if (allowance !== -1) { allowed.splice(allowance, 1); return []; }
      return emDash.test(line) ? [`${path}:${index + 1}`] : [];
    });
  };

  // Both spellings must fail in every tracked surface, including this guard's source.
  for (const spelling of [dash, "\\u" + "2014"]) {
    for (const path of ["README.md", "src/api.ts", "typedoc.json", "tools/check-currency.mjs", "test/readme.test.ts", ".gitattributes", "web/main.ts"]) {
      assert.deepEqual(findings(path, `A public sentence ${spelling} continues.`), [`${path}:1`]);
    }
  }
  for (const [path, lines] of emptyValues) {
    assert.deepEqual(findings(path, lines.join("\n")), []);
    assert.equal(findings(path, [...lines, lines[0]!].join("\n")).length, 1, "extra placeholders must fail");
    assert.equal(findings(path, lines[0]! + ` Extra prose ${dash} must fail.`).length, 1);
  }
  const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
  assert.ok(tracked.includes("AGENTS.md"), "tracked text inventory must not be empty");
  assert.deepEqual(tracked.flatMap((path) => findings(path, read(path))), []);
});
