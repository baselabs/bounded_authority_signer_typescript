// CommonMark is parsed by the same maintained parser used by TypeDoc. Discovery is recursive;
// executable samples are never an independently maintained list of paths.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import MarkdownIt from "markdown-it";

const md = new MarkdownIt({ html: true });
const languages = new Set(["ts", "typescript", "js", "javascript", "tsx", "mjs"]);
export function parse(markdown, source = "README.md") {
  const tokens = md.parse(markdown, {});
  const samples = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.type !== "fence") continue;
    const lang = token.info.trim().split(/\s+/)[0];
    const marker = tokens[i - 1]?.type === "html_block" ? tokens[i - 1].content.trim() : "";
    const line = (token.map?.[0] ?? 0) + 1;
    const code = token.content.replace(/\n$/, "");
    if (marker === "<!-- readme-output -->") {
      const owner = samples.at(-1);
      assert.ok(owner && ["run", "run-dom"].includes(owner.kind) && owner.output === undefined, `${source}:${line}: orphan output`);
      assert.equal(lang, "text");
      owner.output = code;
    } else if (languages.has(lang) || marker === "<!-- readme-sample: setup -->") {
      const match = /^<!-- readme-sample: (run-dom|run|types|setup|file(?:-dom)? ([\w.-]+\.ts)) -->$/.exec(marker);
      assert.ok(match, `${source}:${line}: executable fence needs a sample marker`);
      const kind = match[1].startsWith("file-dom") ? "file-dom" : match[2] ? "file" : match[1];
      const fileName = match[2] ?? `${source.replace(/\W/g, "_")}-${line}.ts`;
      samples.push({ kind, line, code, fileName, source });
    } else if (["bash", "sh", "shell"].includes(lang)) {
      // An install command is a checked setup journey, never a silently skipped shell sample.
      samples.push({ kind: "setup", line, code, fileName: "setup.sh", source });
    }
  }
  for (const sample of samples) if (["run", "run-dom"].includes(sample.kind)) {
    assert.notEqual(sample.output, undefined, `${source}:${sample.line}: executable example needs recorded output`);
  }
  return samples;
}
export function files(root, directory = "") {
  return readdirSync(join(root, directory), { withFileTypes: true }).flatMap((entry) => {
    if ([".git", "node_modules", "dist", "site-dist", "build-pack", ".venv", ".kimosabe", ".playwright-mcp", "__pycache__"].includes(entry.name)) return [];
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(root, path) : [path];
  });
}
export function discover(root) {
  const found = [];
  for (const file of files(root)) {
    const source = relative(root, join(root, file)).replaceAll("\\", "/");
    if (file.endsWith(".md")) found.push(...parse(readFileSync(join(root, file), "utf8"), source));
    if (file.endsWith(".ipynb")) {
      const notebook = JSON.parse(readFileSync(join(root, file), "utf8"));
      for (const [i, cell] of notebook.cells.entries()) {
        const code = Array.isArray(cell.source) ? cell.source.join("") : cell.source;
        if (cell.cell_type === "markdown") found.push(...parse(code, `${source}:markdown-${i + 1}`));
        if (cell.cell_type === "code") {
          const output = (cell.outputs ?? []).filter((o) => o.output_type === "stream" && o.name === "stdout")
            .map((o) => Array.isArray(o.text) ? o.text.join("") : o.text).join("").trimEnd();
          assert.ok(output, `${source}:cell ${i + 1}: missing semantic output`);
          found.push({ kind: "notebook", source, line: i + 1, code, output, fileName: `${source}-${i + 1}` });
        }
      }
    }
    if (source.startsWith("src/") && file.endsWith(".ts")) {
      const text = readFileSync(join(root, file), "utf8");
      for (const match of text.matchAll(/\/\*\*([\s\S]*?)\*\//g)) {
        const comment = match[1].replace(/^\s*\* ?/gm, "");
        if (!/@example\b/.test(comment)) continue;
        const example = comment.split(/@example\s*\n/).slice(1);
        assert.ok(example.length, `${source}: @example must contain executable code`);
        for (const [i, block] of example.entries()) {
          const samples = parse(block, `${source}-${match.index}-${i}`);
          assert.ok(samples.some((s) => ["run", "run-dom"].includes(s.kind)), `${source}: empty example`);
          found.push(...samples);
        }
      }
    }
    if (source.startsWith("web/") && file.endsWith(".html")) {
      const text = readFileSync(join(root, file), "utf8");
      for (const match of text.matchAll(/<pre\b([^>]*data-sample="(run|run-dom)"[^>]*)>([\s\S]*?)<\/pre>/g)) {
        const output = /data-output="([^"]*)"/.exec(match[1]);
        assert.ok(output, `${source}: site example must assert output`);
        found.push({ kind: match[2], line: text.slice(0, match.index).split("\n").length,
          code: md.utils.unescapeAll(match[3]), fileName: `web-example-${found.length}.ts`, source,
          output: md.utils.unescapeAll(output[1]) });
      }
    }
  }
  return found;
}
export function anchors(markdown) {
  const seen = new Map();
  const ids = new Set();
  const tokens = md.parse(markdown, {});
  for (let i = 0; i < tokens.length; i++) if (tokens[i].type === "heading_open") {
    const inline = tokens[i + 1];
    const text = (inline?.children ?? []).map((t) => ["text", "code_inline"].includes(t.type) ? t.content : "").join("");
    const base = text.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/\s/g, "-");
    const count = seen.get(base) ?? 0;
    ids.add(count ? `${base}-${count}` : base); seen.set(base, count + 1);
  }
  for (const match of markdown.matchAll(/\b(?:id|name)=["']([^"']+)["']/g)) ids.add(match[1]);
  return ids;
}
export function links(markdown) {
  const result = [];
  function walk(tokens) {
    for (const token of tokens) {
      if (token.type === "link_open" || token.type === "image") {
        const href = token.attrGet(token.type === "image" ? "src" : "href");
        if (href) result.push(href);
      }
      if (token.type === "html_block" || token.type === "html_inline") {
        for (const m of token.content.matchAll(/\b(?:href|src)=["']([^"']+)["']/g)) result.push(m[1]);
      }
      if (token.children) walk(token.children);
    }
  }
  walk(md.parse(markdown, {})); return result;
}
