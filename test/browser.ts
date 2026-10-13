// The browser lanes (pnpm test:browser): real engines through Playwright, the real signer and verifier
// bundled for the browser by esbuild (platform "browser", so the verifier's "#crypto" import resolves to
// its portable backend the way a browser bundler resolves it), served by a node:http server on
// 127.0.0.1:0 that sends the strict CSP on every response. No jsdom, no mocks.
//
// BAP_BROWSERS selects engines (default "chromium"); CI runs chromium, firefox and webkit on Linux.
// BAP_CHROMIUM_EXECUTABLE points Playwright at a locally installed Chromium build when the bundled
// revision is not installed. The non-secure-context lane needs Chromium's --host-resolver-rules (it maps
// http://bap.test to 127.0.0.1, an origin that is not a secure context), so it runs on Chromium only.
// Linux WebKit is evidence for this pure-JS code only, never for Safari.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { chromium, firefox, webkit, type Browser, type BrowserType } from "playwright";

const REPO = fileURLToPath(new URL("..", import.meta.url));
export const CSP = "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'";
const ENGINES: Record<string, BrowserType> = { chromium, firefox, webkit };
const SELECTED = (process.env.BAP_BROWSERS ?? "chromium").split(",").filter(Boolean);

async function bundle(entry: string): Promise<string> {
  const result = await build({
    entryPoints: [join(REPO, entry)], absWorkingDir: REPO, bundle: true, write: false, format: "esm",
    platform: "browser", target: "es2022", logLevel: "silent",
  });
  return result.outputFiles[0]!.text;
}

const html = (title: string, script: string) =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title><script type="module" src="/${script}"></script></head><body data-state="running"><pre id="out"></pre></body></html>`;

interface Served { server: Server; port: number; requests: string[] }

// Every page and script the lanes use, bundled once per server.
const PAGES: Record<string, { title: string; entry: string }> = {
  insecure: { title: "BAP signer: non-secure-context lane", entry: "browser/insecure.ts" },
};

async function serve(): Promise<Served> {
  const scripts = new Map<string, string>();
  for (const [name, page] of Object.entries(PAGES)) scripts.set(`/${name}.js`, await bundle(page.entry));
  const requests: string[] = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    requests.push(url.pathname);
    const send = (status: number, type: string, body: string) => {
      res.writeHead(status, { "content-type": type, "content-security-policy": CSP, "cache-control": "no-store" });
      res.end(body);
    };
    const name = url.pathname === "/" ? "index" : url.pathname.replace(/^\/|\.html$/g, "");
    const page = PAGES[name];
    if (page !== undefined && (url.pathname === "/" || url.pathname.endsWith(".html"))) return send(200, "text/html; charset=utf-8", html(page.title, `${name}.js`));
    const script = scripts.get(url.pathname);
    if (script !== undefined) return send(200, "text/javascript; charset=utf-8", script);
    return send(404, "text/plain", "not found");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return { server, port: address.port, requests };
}

// Page functions are passed as functions, never as strings: Playwright evaluates a string predicate
// with eval inside the page, which the strict CSP blocks (and reports as a violation).
const pageDone = () => (globalThis as unknown as { document: { body: { dataset: Record<string, string> } } }).document.body.dataset.state === "done";
const pageResult = () => (globalThis as unknown as { __BAP_RESULT__: unknown }).__BAP_RESULT__;

async function launch(name: string, args: string[] = []): Promise<Browser> {
  const executablePath = name === "chromium" ? process.env.BAP_CHROMIUM_EXECUTABLE : undefined;
  return ENGINES[name]!.launch({ ...(executablePath ? { executablePath } : {}), args });
}

for (const name of SELECTED) {
  assert.ok(ENGINES[name], `known engine ${name}`);

  if (name === "chromium") {
    test("chromium: in a non-secure context, a report signed without a proofId is a closed producer_error, never a thrown TypeError", async (t) => {
      const served = await serve();
      const browser = await launch(name, [`--host-resolver-rules=MAP bap.test 127.0.0.1`]);
      try {
        const page = await browser.newPage();
        const response = await page.goto(`http://bap.test:${served.port}/insecure.html`);
        assert.equal(response?.headers()["content-security-policy"], CSP, "the page is served under the strict CSP");
        await page.waitForFunction(pageDone, undefined, { timeout: 120_000 });
        const result = (await page.evaluate(pageResult)) as Record<string, unknown>;
        assert.equal(result.error, null, String(result.error));
        assert.equal(result.backend, "portable");
        assert.equal(result.secure, false, "http://bap.test is not a secure context");
        assert.equal(result.randomUUID, "undefined", "crypto.randomUUID is absent outside a secure context");
        assert.deepEqual(result.defaults, {
          signReport: "error:producer_error",
          signLocalLoopbackReport: "error:producer_error",
          signV2Report: "error:producer_error",
          signV3Report: "error:producer_error",
        });
        assert.equal(result.explicitVerifies, true, "with an explicit proofId the page signs and the envelope verifies");
        assert.deepEqual(result.violations, []);
        t.diagnostic(`chromium ${browser.version()}: ${JSON.stringify(result.defaults)}`);
      } finally {
        await browser.close();
        served.server.close();
      }
    });
  }
}
