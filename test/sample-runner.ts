// Installed-artifact execution shared by the Node and browser documentation journeys.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { transformSync } from "esbuild";
import ts from "typescript";
import { discover, type Sample } from "../tools/documentation.mjs";
import { pack } from "../tools/pack.mjs";

export const ROOT = fileURLToPath(new URL("..", import.meta.url));
export const samples = discover(ROOT);
export type Mode = "candidate" | "published";
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { name: string; version: string; dependencies: Record<string, string> };
export const run = (command: string, args: string[], cwd: string): string => execFileSync(command, args, {
  cwd, encoding: "utf8", timeout: 300_000, stdio: ["ignore", "pipe", "pipe"],
}).trimEnd();
export const filename = (sample: Sample): string => ["file", "file-dom"].includes(sample.kind) ? sample.fileName :
  `sample-${createHash("sha256").update(`${sample.source}:${sample.line}`).digest("hex").slice(0, 20)}.ts`;

export interface Consumer { directory: string; cleanup(): void }
export function prepare(mode: Mode): Consumer {
  const scratch = mkdtempSync(join(tmpdir(), `bap-docs-${mode}-`));
  const directory = join(scratch, "consumer");
  mkdirSync(directory);
  try {
    const metadata = mode === "published" ? JSON.parse(run("npm", ["view", `${pkg.name}@${pkg.version}`, "--json", "--registry=https://registry.npmjs.org"], directory)) as {
      name: string; version: string; dist: { tarball: string; integrity: string };
    } : undefined;
    if (metadata) {
      assert.equal(metadata.name, pkg.name); assert.equal(metadata.version, pkg.version);
      assert.ok(metadata!.dist.tarball.startsWith("https://registry.npmjs.org/"));
    }
    const verifierName = "@bounded-authority-protocol/verifier";
    const verifierVersion = pkg.dependencies[verifierName]!.replace(/^[~^]/, "");
    const verifierMetadata = JSON.parse(run("npm", ["view", `${verifierName}@${verifierVersion}`, "--json", "--registry=https://registry.npmjs.org"], directory)) as NonNullable<typeof metadata>;
    assert.equal(verifierMetadata.name, verifierName); assert.equal(verifierMetadata.version, verifierVersion);
    assert.ok(verifierMetadata.dist.tarball.startsWith("https://registry.npmjs.org/"));
    const artifact = mode === "candidate" ? process.env.BAP_TARBALL ?? pack(join(scratch, "packed")).file : undefined;
    const setups = samples.filter((s) => s.kind === "setup" && s.source === "README.md" && s.code.includes("npm init"));
    assert.equal(setups.length, 1, "one complete reader setup");
    const candidateSpecifier = artifact ? "'" + artifact.replaceAll("'", "'\\''") + "'" : undefined;
    const commands = candidateSpecifier ? setups[0]!.code.replaceAll(`${pkg.name}@${pkg.version}`, candidateSpecifier) : setups[0]!.code;
    run("bash", ["-e", "-c", commands], directory);
    for (const [i, setup] of samples.filter((s) => s.kind === "setup" && s !== setups[0]).entries()) {
      const setupDirectory = join(scratch, `setup-${i}`); mkdirSync(setupDirectory);
      const command = candidateSpecifier ? setup.code.replaceAll(`${pkg.name}@${pkg.version}`, candidateSpecifier) : setup.code;
      run("bash", ["-e", "-c", command], setupDirectory);
      const setupLock = JSON.parse(readFileSync(join(setupDirectory, "package-lock.json"), "utf8"));
      const setupEntry = setupLock.packages[`node_modules/${pkg.name}`];
      assert.equal(setupEntry.version, pkg.version, `${setup.source}: setup version`);
      assert.ok(mode === "candidate" ? setupEntry.resolved.startsWith("file:") : setupEntry.resolved === metadata!.dist.tarball,
        `${setup.source}: setup origin`);
    }
    const lock = JSON.parse(readFileSync(join(directory, "package-lock.json"), "utf8")) as {
      packages: Record<string, { version: string; resolved?: string; integrity?: string }>;
    };
    const installed = JSON.parse(readFileSync(join(directory, "node_modules", pkg.name, "package.json"), "utf8")) as { name: string; version: string };
    assert.equal(installed.name, pkg.name); assert.equal(installed.version, pkg.version);
    const verifier = lock.packages[`node_modules/${verifierName}`]!;
    assert.equal(verifier.version, verifierVersion);
    assert.equal(verifier.resolved, verifierMetadata.dist.tarball);
    assert.equal(verifier.integrity, verifierMetadata.dist.integrity);
    const entry = lock.packages[`node_modules/${pkg.name}`]!;
    if (mode === "published") {
      // Version equality never chooses a local artifact. Registry tarball and integrity must agree.
      assert.equal(entry.resolved, metadata!.dist.tarball);
      assert.equal(entry.integrity, metadata!.dist.integrity);
      assert.ok(!entry.resolved.startsWith("file:"));
    } else {
      assert.ok(artifact && entry.resolved?.startsWith("file:"), "candidate must be the explicitly selected tarball");
      const digest = "sha512-" + createHash("sha512").update(readFileSync(artifact)).digest("base64");
      assert.equal(entry.integrity, digest, "installed candidate must be the inspected archive");
    }
    const seen = new Map<string, string>();
    for (const sample of samples.filter((s) => !["setup", "notebook"].includes(s.kind))) {
      const name = filename(sample);
      if (seen.has(name)) assert.equal(seen.get(name), sample.code, `conflicting helper ${name}`);
      seen.set(name, sample.code);
      let code = sample.code;
      if (sample.kind === "types") {
        const names = [...code.matchAll(/^(?:export\s+)?(?:interface|type)\s+(\w+)/gm)].map((m) => m[1]!);
        code += `\nimport type * as __Package from "${pkg.name}";\ntype __Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;\n` +
          names.map((name) => `export const __same_${name}: __Same<${name}, __Package.${name}> = true;`).join("\n");
      }
      writeFileSync(join(directory, name), code + "\n");
    }
    return { directory, cleanup: () => { rmSync(scratch, { recursive: true, force: true }); assert.ok(!existsSync(scratch)); } };
  } catch (error) { rmSync(scratch, { recursive: true, force: true }); throw error; }
}

export function typecheck(directory: string, browser: boolean): void {
  const names = [...new Set(samples.filter((s) => browser ? ["run-dom", "file-dom"].includes(s.kind) : ["run", "file", "types"].includes(s.kind)).map(filename))];
  const config = join(directory, browser ? "tsconfig.dom.json" : "tsconfig.node.json");
  writeFileSync(config, JSON.stringify({ compilerOptions: {
    target: "ES2022", module: browser ? "ESNext" : "NodeNext", moduleResolution: browser ? "Bundler" : "NodeNext",
    lib: browser ? ["ES2023", "DOM", "DOM.Iterable"] : ["ES2023"], types: browser ? [] : ["node"],
    typeRoots: [join(ROOT, "node_modules/@types")], strict: true, skipLibCheck: false, noEmit: true,
  }, files: names }));
  const parsed = ts.getParsedCommandLineOfConfigFile(config, {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} });
  assert.ok(parsed);
  const program = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options });
  const diagnostics = ts.getPreEmitDiagnostics(program).map((d) => `${d.file?.fileName}:${d.start}: TS${d.code} ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`);
  assert.deepEqual(diagnostics, [], `installed ${browser ? "DOM" : "Node"} declarations`);
}
export function executeNode(directory: string): void {
  for (const sample of samples.filter((s) => ["file", "run"].includes(s.kind))) {
    const file = filename(sample);
    writeFileSync(join(directory, file.replace(/\.ts$/, ".js")), transformSync(sample.code, { loader: "ts", format: "esm", target: "es2022" }).code);
  }
  for (const sample of samples.filter((s) => s.kind === "run")) {
    const result = run("npx", ["--no-install", "tsx", join(directory, filename(sample))], directory);
    assert.equal(result, sample.output, `${sample.source}:${sample.line}: recorded output`);
  }
}
