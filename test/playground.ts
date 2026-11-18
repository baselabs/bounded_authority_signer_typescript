// The built public playground and every DOM documentation example, in real browser engines.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { build } from "esbuild";
import { chromium, firefox, webkit, type BrowserType } from "playwright";
import { filename, prepare, ROOT, samples, typecheck, type Mode } from "./sample-runner.js";

const engines: Record<string, BrowserType> = { chromium, firefox, webkit };
const selected = (process.env.BAP_BROWSERS ?? "chromium").split(",");
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'";
async function serve(scripts = new Map<string, string>()) {
  const server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
    res.setHeader("content-security-policy", CSP);
    res.setHeader("cache-control", "no-store");
    if (path === "/sample.html") {
      res.setHeader("content-type", "text/html");
      return res.end('<!doctype html><html><head><script type="module" src="/sample.js"></script></head><body></body></html>');
    }
    if (scripts.has(path)) { res.setHeader("content-type", "text/javascript"); return res.end(scripts.get(path)); }
    const file = path === "/" ? "index.html" : path.slice(1);
    if (!["index.html", "app.js", "styles.css"].includes(file)) { res.writeHead(404); return res.end(); }
    res.setHeader("content-type", file.endsWith(".html") ? "text/html" : file.endsWith(".css") ? "text/css" : "text/javascript");
    res.end(readFileSync(join(ROOT, "site-dist", file)));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address === "object");
  return { url: `http://127.0.0.1:${address.port}`, close: async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  } };
}
for (const name of selected) {
  assert.ok(engines[name], name);
  test(`${name}: built playground, every major, custody path, tamper control, selector refusal and reset`, async () => {
    const served = await serve();
    let browser;
    try {
      browser = await engines[name]!.launch();
      const page = await browser.newPage();
      const errors: string[] = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.goto(served.url);
      await page.waitForFunction(() => (globalThis as unknown as { document: { body: { dataset: Record<string, string> } } }).document.body.dataset.ready === "true");
      for (const major of ["1", "2", "3"]) for (const custody of ["webcrypto", "noble"]) {
        await page.selectOption("#contract-major", major);
        await page.waitForFunction(() => (globalThis as unknown as { document: { body: { dataset: Record<string, string> } } }).document.body.dataset.ready === "true");
        await page.selectOption("#custody", custody);
        await page.waitForFunction(() => (globalThis as unknown as { document: { body: { dataset: Record<string, string> } } }).document.body.dataset.ready === "true");
        await page.click("#btn-grant");
        await page.waitForFunction(() => !(globalThis as unknown as { document: { querySelector(s: string): { disabled: boolean } } }).document.querySelector("#btn-proof").disabled);
        await page.click("#btn-proof");
        await page.waitForFunction(() => !(globalThis as unknown as { document: { querySelector(s: string): { disabled: boolean } } }).document.querySelector("#btn-verify").disabled);
        await page.click("#btn-verify");
        assert.equal(await page.locator("#verdict").getAttribute("data-state"), "ok");
        const controls = await page.locator("[data-tamper]").count();
        assert.ok(controls >= 5);
        for (let i = 0; i < controls; i++) {
          await page.locator("[data-tamper]").nth(i).click();
          await page.waitForFunction(() => (globalThis as unknown as { document: { querySelector(s: string): { getAttribute(s: string): string | null } | null } }).document.querySelector("#verdict")?.getAttribute("data-state") === "fail");
          assert.deepEqual(JSON.parse(await page.locator("#facts-body").innerText()), { ok: false });
          await page.click("#btn-verify");
          assert.equal(await page.locator("#verdict").getAttribute("data-state"), "ok");
        }
        await page.click("#selector-refusal");
        await page.waitForFunction(() => (globalThis as unknown as { document: { querySelector(s: string): { textContent: string | null } | null } }).document.querySelector("#selector-result")?.textContent === "producer_error");
        const before = await page.locator("#chip-holder .thumb").innerText();
        await page.click("#reset");
        await page.waitForFunction(() => (globalThis as unknown as { document: { body: { dataset: Record<string, string> } } }).document.body.dataset.ready === "true");
        assert.notEqual(await page.locator("#chip-holder .thumb").innerText(), before);
        assert.equal(await page.locator("#btn-proof").isDisabled(), true);
        assert.equal(await page.locator("#btn-verify").isDisabled(), true);
        assert.equal(await page.locator("#slot-grant").innerText(), "");
        assert.equal(await page.locator("#slot-proof").innerText(), "");
      }
      assert.deepEqual(errors, []);
    } finally { await browser?.close(); await served.close(); }
  });

  for (const mode of ["candidate", "published"] as Mode[]) test(`${name}/${mode}: all DOM examples typecheck installed declarations and execute in the browser`, async () => {
    const consumer = prepare(mode);
    let browser;
    const scripts = new Map<string, string>();
    const served = await serve(scripts);
    try {
      typecheck(consumer.directory, true);
      // Real worker helpers are independent browser modules served alongside sample modules.
      for (const helper of samples.filter((s) => s.kind === "file-dom")) {
        const result = await build({ entryPoints: [join(consumer.directory, filename(helper))], absWorkingDir: consumer.directory,
          bundle: true, write: false, format: "esm", platform: "browser", target: "es2022" });
        scripts.set("/" + helper.fileName.replace(/\.ts$/, ".js"), result.outputFiles[0]!.text);
      }
      browser = await engines[name]!.launch();
      const runnable = samples.filter((s) => s.kind === "run-dom");
      assert.ok(runnable.length > 15);
      for (const sample of runnable) {
        const built = await build({ entryPoints: [join(consumer.directory, filename(sample))], absWorkingDir: consumer.directory,
          bundle: true, write: false, format: "esm", platform: "browser", target: "es2022" });
        scripts.set("/sample.js", built.outputFiles[0]!.text + '\ndocument.body.dataset.state = "done";\n');
        const page = await browser.newPage();
        const printed: string[] = [], errors: string[] = [];
        page.on("console", (message) => { if (message.type() === "log") printed.push(message.text()); });
        page.on("pageerror", (error) => errors.push(error.message));
        try {
          await page.goto(served.url + "/sample.html");
          await page.waitForFunction(() => (globalThis as unknown as { document: { body: { dataset: Record<string, string> } } }).document.body.dataset.state === "done", undefined, { timeout: 60_000 });
          assert.deepEqual(errors, [], `${sample.source}:${sample.line}`);
          assert.equal(printed.join("\n"), sample.output, `${sample.source}:${sample.line}`);
        } finally { await page.close(); }
      }
      // The harness owns only an isolated consumer, and cleanup removes every installed artifact.
      assert.ok(readdirSync(consumer.directory).length > 0);
    } finally { await browser?.close(); await served.close(); consumer.cleanup(); }
  });
}
