import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { test } from "node:test";
import { parse } from "yaml";

interface Step {
  id?: string;
  run?: string;
  uses?: string;
  env?: Record<string, string>;
  with?: Record<string, unknown>;
}
interface Job {
  steps: Step[];
  needs?: string | string[];
  outputs?: Record<string, string>;
  strategy?: { matrix: { node: string; include: { os: string; node: string }[] } };
}
interface Workflow { jobs?: Record<string, Job>; runs?: { steps: Step[] } }

const read = (file: string): string => readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
const reader = 'scripts/toolchain.sh >> "$GITHUB_OUTPUT"';
const refusal = 'scripts/toolchain.sh --installed "nodejs=$TOOLCHAIN_NODE_VERSION"';

function yamlFiles(directory: URL): URL[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = new URL(entry.name, directory);
    return entry.isDirectory() ? yamlFiles(new URL(`${entry.name}/`, directory))
      : /\.ya?ml$/.test(entry.name) ? [file] : [];
  });
}

test("the shared toolchain reader keeps its exact bytes and executable mode", () => {
  const file = new URL("../scripts/toolchain.sh", import.meta.url);
  assert.equal(createHash("sha256").update(readFileSync(file)).digest("hex"),
    "b29bfeb6ec4ec8f5b7e3ac3c963f04b6d3c73483172e5bd59ea40f20b102f1eb");
  assert.equal(statSync(file).mode & 0o777, 0o755);
});

test("all runtime setup uses shared outputs and checks Node immediately after installation", () => {
  const files = yamlFiles(new URL("../.github/", import.meta.url));
  const setups: Record<string, [string, string]> = {
    "actions/setup-node": ["nodejs", "node-version"],
    "actions/setup-python": ["python", "python-version"],
    "denoland/setup-deno": ["deno", "deno-version"],
    "oven-sh/setup-bun": ["bun", "bun-version"],
    "astral-sh/setup-uv": ["uv", "version"],
  };
  assert.ok(files.length > 0);
  let installations = 0;
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    assert.doesNotMatch(source, /(?:[\w-]+-)?version-file:|\.tool-versions/, file.pathname);
    assert.doesNotMatch(source, /\bbash\s+scripts\/toolchain\.sh/, file.pathname);
    const workflow = parse(source) as Workflow;
    const groups = Object.entries(workflow.jobs ?? {});
    if (workflow.runs) groups.push(["composite", { steps: workflow.runs.steps }]);
    for (const [name, job] of groups) {
      const steps = job.steps;
      const pinIndex = steps.findIndex(step => step.id === "pins" && step.run === reader);
      for (const [index, step] of steps.entries()) {
        if (step.run?.includes("--installed")) assert.equal(step.run, refusal, file.pathname);
        const setup = setups[step.uses?.split("@")[0] ?? ""];
        if (!setup) continue;
        installations++;
        const [tool, input] = setup;
        const matrixLane = file.pathname.endsWith("/workflows/ci.yml") && name === "verify";
        const expected = matrixLane ? "${{ matrix.node }}" : `\${{ steps.pins.outputs.${tool} }}`;
        if (!matrixLane) assert.ok(pinIndex >= 0 && pinIndex < index, `${file.pathname}: ${name}: reader before setup`);
        assert.equal(step.with?.[input], expected, `${file.pathname}: ${name}: ${tool}`);
        if (tool === "nodejs") {
          const check = steps[index + 1];
          assert.equal(check?.run, refusal, `${file.pathname}: ${name}: Node refusal after setup`);
          assert.equal(check?.env?.TOOLCHAIN_NODE_VERSION, expected, `${file.pathname}: ${name}: check the installed lane`);
        }
      }
    }
  }
  assert.ok(installations > 0, "runtime setup inventory must not be empty");
});

test("the Node matrix uses shared default and compatibility outputs", () => {
  const ci = parse(read(".github/workflows/ci.yml")) as Workflow;
  const toolchain = ci.jobs!.toolchain!;
  assert.ok(toolchain.steps.some(step => step.id === "pins" && step.run === reader));
  assert.deepEqual(toolchain.outputs, {
    nodejs: "${{ steps.pins.outputs.nodejs }}",
    nodejs_lanes: "${{ steps.pins.outputs.nodejs_lanes }}",
  });
  const verify = ci.jobs!.verify!;
  assert.equal(verify.needs, "toolchain");
  assert.equal(verify.strategy!.matrix.node, "${{ fromJSON(needs.toolchain.outputs.nodejs_lanes) }}");
  assert.deepEqual(verify.strategy!.matrix.include, [{ os: "ubuntu-24.04", node: "${{ needs.toolchain.outputs.nodejs }}" }]);
  assert.ok(read(".github/workflows/ci.yml").includes("matrix.node == needs.toolchain.outputs.nodejs && 'nodejs' || 'nodejs-next'"),
    "keep the existing qualification check names");
});

test("notebook runtime checks consume shared outputs and check only Node", () => {
  const runner = read("scripts/check_notebooks.py");
  assert.ok(runner.includes('toolchain = str(ROOT / "scripts/toolchain.sh")'));
  assert.ok(runner.includes('run(toolchain, cwd=ROOT, env=dict(os.environ))'));
  assert.ok(runner.includes('run(toolchain, "--installed", f"nodejs={pins[\'nodejs\']}", cwd=scratch, env=env)'));
  assert.doesNotMatch(runner, /\.tool-versions|--version/);
});

test("the lock cannot resolve this repository's own package from a registry", () => {
  const manifest = JSON.parse(read("package.json")) as { name: string };
  const escaped = manifest.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  assert.doesNotMatch(read("pnpm-lock.yaml"), new RegExp(`${escaped}@[^\\s'\"]+`));
});
