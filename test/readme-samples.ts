// The README's code samples, as test/readme.test.ts and test/reader.ts read them. Each fence a reader
// would copy carries a marker on the line before it:
//
//   <!-- readme-sample: file NAME -->  a module the other samples import (typechecked with them)
//   <!-- readme-sample: run -->        typechecked under tsconfig.json (Node types), then run
//   <!-- readme-sample: run-dom -->    typechecked under tsconfig.browser.json (DOM library, no Node types), then run
//   <!-- readme-sample: types -->      exported declarations, compared text for text with the source
//   <!-- readme-sample: setup -->      a bash fence: the shell commands that prepare an empty directory for
//                                      the Quickstart (run verbatim by test/reader.ts)
//   <!-- readme-output -->             before a text fence: the exact console output of the run sample above it
//
// A ts/typescript/js fence without a marker is an error.
import assert from "node:assert/strict";

export type Kind = "file" | "run" | "run-dom" | "types" | "setup";
export interface Sample {
  readonly kind: Kind;
  readonly line: number;      // 1-based line of the opening fence
  readonly code: string;
  readonly fileName: string;
  output?: string;
}

export function parse(markdown: string): Sample[] {
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
    } else if (marker === "<!-- readme-sample: setup -->") {
      assert.equal(lang, "bash", `README.md:${i + 1}: a setup block is a bash fence`);
      samples.push({ kind: "setup", line: i + 1, code: body, fileName: "setup.sh" });
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
