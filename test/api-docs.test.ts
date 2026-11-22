import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const options = JSON.parse(readFileSync(join(REPO, "typedoc.json"), "utf8")) as Record<string, unknown>;

test("API docs: exports-map discovery covers every code entry point and rejects undocumented exports", () => {
  // Use the real TypeDoc CLI and the project's validation settings. The fixture has no services,
  // cryptography, or store; it is an isolated package with two independently exported entry points.
  const dir = mkdtempSync(join(tmpdir(), "bap-api-"));
  try {
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      name: "api-reference-fixture", version: "2.0.0", type: "module",
      exports: {
        ".": { types: "./dist/index.d.ts", default: "./dist/index.js" },
        "./additional": { types: "./dist/additional.d.ts", default: "./dist/additional.js" },
        "./package.json": "./package.json",
      },
    }));
    writeFileSync(join(dir, "tsconfig.build.json"), JSON.stringify({
      compilerOptions: { target: "ES2022", module: "NodeNext", rootDir: "src", outDir: "dist", declaration: true, types: [] },
      include: ["src/**/*.ts"],
    }));
    writeFileSync(join(dir, "typedoc.json"), JSON.stringify({ ...options, readme: "none", projectDocuments: [], disableSources: true }));
    const run = () => {
      const result = spawnSync(process.execPath, [join(REPO, "node_modules/typedoc/bin/typedoc")], {
        cwd: dir, encoding: "utf8", timeout: 60_000,
      });
      assert.ifError(result.error);
      return { status: result.status, output: result.stdout + result.stderr };
    };
    const documented = "/** A documented value. */\nexport const documented: number = 1;\n";
    for (const name of ["index", "additional"]) writeFileSync(join(dir, "src", `${name}.ts`), documented);
    let result = run();
    assert.equal(result.status, 0, result.output);
    assert.match(readFileSync(join(dir, "site-dist/api/index.html"), "utf8"), /api-reference-fixture[^<]*2\.0\.0/);

    for (const name of ["index", "additional"]) {
      const path = join(dir, "src", `${name}.ts`);
      writeFileSync(path, documented + "export const undocumented: number = 2;\n");
      result = run();
      assert.notEqual(result.status, 0, `${name}: an undocumented export must fail the build`);
      assert.match(result.output, /undocumented.*does not have any documentation/);
      writeFileSync(path, documented);
    }

    const memberPath = join(dir, "src/index.ts");
    const memberFixture = (propertyDoc: string, methodDoc: string) => documented + `
/** A public key identity with documented members. */
export interface PublicIdentity {
  ${propertyDoc}
  readonly keyId: string;
  ${methodDoc}
  publicKey(): Uint8Array;
}
`;
    const propertyDoc = "/** The stable key identifier. */";
    const methodDoc = "/** Read the selected suite's public key. */";
    writeFileSync(memberPath, memberFixture(propertyDoc, methodDoc));
    result = run();
    assert.equal(result.status, 0, result.output);
    for (const [member, source] of [
      ["keyId", memberFixture("", methodDoc)],
      ["publicKey", memberFixture(propertyDoc, "")],
    ]) {
      writeFileSync(memberPath, source!);
      result = run();
      assert.notEqual(result.status, 0, `${member}: an undocumented member must fail the build`);
      assert.match(result.output, new RegExp(`${member}.*does not have any documentation`));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
