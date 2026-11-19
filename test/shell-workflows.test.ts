import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

interface RunDefaults { run?: { shell?: string } }
interface RunStep { name?: string; run?: string; shell?: string }
interface Workflow {
  defaults?: RunDefaults;
  jobs?: Record<string, { defaults?: RunDefaults; steps?: RunStep[] }>;
}
interface Action { runs?: { using?: string; steps?: RunStep[] } }

function assertFailuresPropagate(source: string, path: string): void {
  const commands = source.replace(/\\\r?\n/g, "");
  assert.doesNotMatch(commands, /\|\|\s*(?:true\b|:(?=\s|;|$))/, `${path}: never discard a command failure`);
  // Quoted arguments may span lines; stop at command separators outside quotes.
  const substitutedArgument = String.raw`(?:[^;|&\n"'\\]|\\[\s\S]|'[^']*'|"(?:[^"\\]|\\[\s\S])*")*(?:"(?:[^"\\]|\\[\s\S])*)?\$\(`;
  assert.doesNotMatch(commands,
    new RegExp(String.raw`\b(?:echo|printf)\b${substitutedArgument}`),
    `${path}: capture command output before printing it`);
  assert.doesNotMatch(commands, new RegExp(String.raw`\bfor\s+\w+\s+in\b${substitutedArgument}`),
    `${path}: capture command output before iterating`);
  assert.doesNotMatch(commands, /<\(/, `${path}: capture command output instead of process substitution`);
  assert.doesNotMatch(commands, /\b(?:local|declare|export|readonly)\s+[^;\n]*\$\(/,
    `${path}: capture command output separately from a declaration`);
}

test("workflows, composite actions and tracked shell scripts preserve command failures", () => {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const files = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
    .split("\0").filter(Boolean).map((path) => ({ path, source: readFileSync(join(root, path), "utf8") }));
  const workflows = files.filter(({ path }) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path));
  const actions = files.filter(({ path }) => /(?:^|\/)action\.ya?ml$/.test(path));
  const scripts = files.filter(({ path, source }) => /\.(?:sh|bash|dash|ksh|zsh)$/.test(path)
    || /^#![^\n]*\b(?:sh|bash|dash|ksh|zsh)(?:\s|$)/.test(source));
  assert.ok(workflows.length > 0, "workflow inventory must not be empty");
  assert.ok(scripts.length > 0, "shell script inventory must not be empty");

  for (const { path, source } of workflows) {
    const workflow = parse(source) as Workflow;
    assert.equal(workflow.defaults?.run?.shell, "bash", `${path}: workflows require defaults.run.shell: bash`);
    for (const [name, job] of Object.entries(workflow.jobs ?? {})) {
      if (job.defaults?.run?.shell !== undefined) {
        assert.equal(job.defaults.run.shell, "bash", `${path}: ${name} must preserve the Bash default`);
      }
      for (const step of job.steps ?? []) {
        if (step.run !== undefined) {
          if (step.shell !== undefined) assert.equal(step.shell, "bash", `${path}: ${step.name ?? name} must use Bash`);
          assertFailuresPropagate(step.run, `${path}: ${step.name ?? name}`);
        }
      }
    }
    assertFailuresPropagate(source, path);
  }

  let composites = 0;
  for (const { path, source } of actions) {
    const action = parse(source) as Action;
    if (action.runs?.using !== "composite") continue;
    composites++;
    assert.ok(Array.isArray(action.runs.steps), `${path}: composite action requires steps`);
    for (const step of action.runs.steps) {
      if (step.run !== undefined) {
        assert.equal(step.shell, "bash", `${path}: ${step.name ?? "run step"} requires shell: bash`);
        assertFailuresPropagate(step.run, `${path}: ${step.name ?? "run step"}`);
      }
    }
    assertFailuresPropagate(source, path);
  }
  assert.ok(composites > 0, "composite action inventory must not be empty");

  for (const { path, source } of scripts) {
    const lines = source.split(/\r?\n/);
    assert.equal(lines[0], "#!/usr/bin/env bash", `${path}: shell scripts require the Bash shebang`);
    const firstStatement = lines.slice(1).find((line) => line.trim() !== "" && !line.trimStart().startsWith("#"));
    const flags = firstStatement?.trim().match(/^set -([a-z]+) pipefail(?:\s+#.*)?$/)?.[1];
    assert.ok(flags, `${path}: strict mode must be the first statement`);
    for (const flag of ["e", "u", "o"]) assert.ok(flags.includes(flag), `${path}: strict mode requires -${flag}`);
    assertFailuresPropagate(source, path);
  }
});
