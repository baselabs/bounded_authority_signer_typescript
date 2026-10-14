// Every type a public declaration names must itself be importable from the package root. The test walks
// the type annotations of everything src/index.ts exports (function parameters, return types, interface
// members, type aliases), follows each type reference transitively, and fails for any type declared in
// this package's src/ that the root does not export: such a type is reachable only through a deep import.
// Types from the verifier package (Bounds, Tagged, OperationInput, ...) are public there, so they are not
// required here. An exported function must annotate its return type, so nothing inferred escapes the walk.
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const SRC = join(REPO, "src");
const INDEX = join(SRC, "index.ts");

/** The names of the src/ types reachable from the root's exports but not exported by it. */
export function unexportedReachableTypes(rootFile: string = INDEX): { missing: string[]; walked: number; problems: string[] } {
  const parsed = ts.getParsedCommandLineOfConfigFile(join(REPO, "tsconfig.build.json"), {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} });
  assert.ok(parsed, "tsconfig.build.json parses");
  const program = ts.createProgram({ rootNames: [rootFile], options: parsed.options });
  const checker = program.getTypeChecker();
  const root = program.getSourceFile(rootFile);
  assert.ok(root, "the root source file loads");
  const moduleSymbol = checker.getSymbolAtLocation(root);
  assert.ok(moduleSymbol, "the root is a module");

  const resolve = (s: ts.Symbol): ts.Symbol => (s.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(s) : s);
  const exported = new Set(checker.getExportsOfModule(moduleSymbol).map(resolve));
  const inSrc = (s: ts.Symbol): boolean => (s.declarations ?? []).some((d) => d.getSourceFile().fileName.startsWith(SRC));

  const seen = new Set<ts.Symbol>();
  const missing = new Set<string>();
  const problems: string[] = [];
  const queue: ts.Symbol[] = [...exported];

  // The type positions of a declaration: never a function body.
  function typeNodes(decl: ts.Declaration): ts.Node[] {
    if (ts.isFunctionDeclaration(decl)) {
      if (decl.type === undefined) problems.push(`${decl.name?.text ?? "?"}: an exported function must annotate its return type`);
      return [...(decl.typeParameters ?? []), ...decl.parameters.map((p) => p.type).filter((t) => t !== undefined), ...(decl.type ? [decl.type] : [])];
    }
    if (ts.isInterfaceDeclaration(decl) || ts.isTypeAliasDeclaration(decl)) return [decl];
    if (ts.isVariableDeclaration(decl)) {
      if (decl.type === undefined) problems.push(`${decl.name.getText()}: an exported value must annotate its type`);
      return decl.type ? [decl.type] : [];
    }
    return [];
  }

  function visit(node: ts.Node): void {
    let name: ts.Node | undefined;
    if (ts.isTypeReferenceNode(node)) name = node.typeName;
    else if (ts.isExpressionWithTypeArguments(node)) name = node.expression;
    else if (ts.isTypeQueryNode(node)) name = node.exprName;
    if (name !== undefined) {
      const ref = checker.getSymbolAtLocation(ts.isQualifiedName(name) ? name.right : name);
      if (ref !== undefined) {
        const target = resolve(ref);
        if (inSrc(target) && !(target.flags & ts.SymbolFlags.TypeParameter)) {
          if (!exported.has(target)) missing.add(target.getName());
          queue.push(target);
        }
      }
    }
    ts.forEachChild(node, visit);
  }

  while (queue.length > 0) {
    const symbol = queue.pop()!;
    if (seen.has(symbol)) continue;
    seen.add(symbol);
    for (const decl of symbol.declarations ?? []) for (const node of typeNodes(decl)) visit(node);
  }
  return { missing: [...missing].sort(), walked: seen.size, problems };
}

test("exports: every src/ type reachable from a public declaration is exported from the package root", () => {
  const { missing, walked, problems } = unexportedReachableTypes();
  assert.deepEqual(problems, []);
  assert.ok(walked >= 40, `the walk reached ${walked} symbols`);
  assert.deepEqual(missing, [], `reachable from the public API but not exported by src/index.ts: ${missing.join(", ")}`);
});
