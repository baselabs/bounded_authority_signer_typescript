// The browser lanes (pnpm test:browser): real engines through Playwright, the real signer and verifier
// bundled for the browser by esbuild (platform "browser", so the verifier's "#crypto" import resolves to
// its portable backend the way a browser bundler resolves it), served by a node:http server on
// 127.0.0.1:0 that sends the strict CSP on every response. No jsdom, no mocks.
//
// BAP_BROWSERS selects engines (default "chromium"); CI runs chromium, firefox and webkit on Linux.
// BAP_CHROMIUM_EXECUTABLE points Playwright at a locally installed Chromium build when the bundled
// revision is not installed. The non-secure-context lane runs on every engine: Playwright routes
// http://bap.test (an origin that is not a secure context) to the lane server.
// Linux WebKit is evidence for the pure-JS code only, never for Safari; for the WebCrypto key handles,
// which call each engine's own WebCrypto, it is evidence for that WebKit build only.
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

async function bundle(entry: string, format: "esm" | "iife" = "esm"): Promise<string> {
  const result = await build({
    entryPoints: [join(REPO, entry)], absWorkingDir: REPO, bundle: true, write: false, format,
    platform: "browser", target: "es2022", logLevel: "silent",
  });
  return result.outputFiles[0]!.text;
}

const html = (title: string, script: string) =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title><script type="module" src="/${script}"></script></head><body data-state="running"><pre id="out"></pre></body></html>`;

interface Served { server: Server; port: number; requests: string[] }

// Every page and script the lanes use, bundled once per server.
const PAGES: Record<string, { title: string; entry: string }> = {
  index: { title: "BAP signer: browser sign-then-verify lane", entry: "browser/main.ts" },
  insecure: { title: "BAP signer: non-secure-context lane", entry: "browser/insecure.ts" },
  "eval-probe": { title: "BAP signer: CSP probe", entry: "browser/eval-probe.ts" },
};

async function serve(): Promise<Served> {
  const scripts = new Map<string, string>();
  for (const [name, page] of Object.entries(PAGES)) scripts.set(`/${name}.js`, await bundle(page.entry));
  scripts.set("/key-worker.js", await bundle("browser/key-worker.ts", "iife")); // the F9 worker, a classic script
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

interface L2Result {
  backend: string; secure: boolean; userAgent: string; violations: string[]; error: string | null; ms: number;
  report: { checks: Record<string, boolean>; trials: number; highS: number } | null;
  webcrypto: { checks: Record<string, boolean>; capability: Record<string, unknown>; observed: { proxySymbolFlip: string } } | null;
}

for (const name of SELECTED) {
  assert.ok(ENGINES[name], `known engine ${name}`);

  test(`${name}: BACKEND_ID portable in a secure context under the strict CSP; v1, v2 and v3 sign then verify (L2) with low-S holding (L3)`, async (t) => {
    const served = await serve();
    const browser = await launch(name).catch((e: unknown) => { served.server.close(); throw e; }); // a failed launch must not leave the server holding the process open
    try {
      const page = await browser.newPage();
      const response = await page.goto(`http://127.0.0.1:${served.port}/`);
      assert.equal(response?.headers()["content-security-policy"], CSP, "the page is served under the strict CSP");
      await page.waitForFunction(pageDone, undefined, { timeout: 120_000 });
      const result = (await page.evaluate(pageResult)) as L2Result;
      assert.equal(result.error, null, String(result.error));
      assert.equal(result.backend, "portable");
      assert.equal(result.secure, true);
      assert.deepEqual(result.violations, [], "no CSP violation while signing and verifying");
      assert.ok(result.report);
      const failed = Object.entries(result.report.checks).filter(([, v]) => !v).map(([k]) => k);
      assert.deepEqual(failed, []);
      assert.ok(Object.keys(result.report.checks).length >= 23);
      assert.ok(result.report.highS > 0, "the L3 sample contains high-S raw signatures");
      t.diagnostic(`${name} ${browser.version()} (${result.userAgent}): ${Object.keys(result.report.checks).length} checks, ${result.report.trials} v3 trials, ${result.report.highS} high-S normalized, ${result.ms} ms`);
      // The WebCrypto key handles with the engine's own non-extractable keys (design §12.8).
      assert.ok(result.webcrypto);
      const wcFailed = Object.entries(result.webcrypto.checks).filter(([, v]) => !v).map(([k]) => k);
      assert.deepEqual(wcFailed, []);
      assert.ok(Object.keys(result.webcrypto.checks).length >= 93, `${Object.keys(result.webcrypto.checks).length} key-handle checks`);
      assert.ok(Object.keys(result.webcrypto.checks).some((k) => k.startsWith("R10 an iframe")), "the iframe-realm rows ran");
      assert.ok(Object.keys(result.webcrypto.checks).some((k) => k.startsWith("R10 (F9) a worker-posted")), "the worker-posted rows ran");
      assert.equal(result.webcrypto.capability.ed25519Generate, true, "the engine generates Ed25519 keys (never skipped)");
      assert.equal(result.webcrypto.capability.ecdsaP256Generate, true);
      assert.equal(result.webcrypto.observed.proxySymbolFlip, "error:invalid_key_handle", "T4b: the engine's getter refuses a Proxy");
      t.diagnostic(`${name} ${browser.version()}: ${Object.keys(result.webcrypto.checks).length} key-handle checks; T4b ${result.webcrypto.observed.proxySymbolFlip}; capability ${JSON.stringify(result.webcrypto.capability)}`);
    } finally {
      await browser.close();
      served.server.close();
    }
  });

  test(`${name}: red-proof: a page expecting the wrong backend runs no check`, async () => {
    const served = await serve();
    const browser = await launch(name).catch((e: unknown) => { served.server.close(); throw e; }); // a failed launch must not leave the server holding the process open
    try {
      const page = await browser.newPage();
      await page.goto(`http://127.0.0.1:${served.port}/?expect=node`);
      await page.waitForFunction(pageDone, undefined, { timeout: 60_000 });
      const result = (await page.evaluate(pageResult)) as L2Result;
      assert.match(result.error ?? "", /BACKEND_ID is "portable", this lane expects "node"; no check was run/);
      assert.equal(result.report, null);
    } finally {
      await browser.close();
      served.server.close();
    }
  });

  test(`${name}: red-proof: eval is blocked by the served CSP and the securitypolicyviolation listener records it`, async () => {
    const served = await serve();
    const browser = await launch(name).catch((e: unknown) => { served.server.close(); throw e; }); // a failed launch must not leave the server holding the process open
    try {
      const page = await browser.newPage();
      await page.goto(`http://127.0.0.1:${served.port}/eval-probe.html`);
      await page.waitForFunction(pageDone, undefined, { timeout: 60_000 });
      const probe = (await page.evaluate(pageResult)) as { evalBlocked: boolean; violations: string[] };
      assert.equal(probe.evalBlocked, true);
      assert.ok(probe.violations.some((v) => v.startsWith("script-src")), JSON.stringify(probe.violations));
    } finally {
      await browser.close();
      served.server.close();
    }
  });

  test(`${name}: in a non-secure context, a report signed without a proofId is a closed producer_error, and both key-handle factories refuse (T11) without touching their arguments`, async (t) => {
    const served = await serve();
    const browser = await launch(name).catch((e: unknown) => { served.server.close(); throw e; }); // a failed launch must not leave the server holding the process open
    try {
      const context = await browser.newContext();
      // http://bap.test is not a secure context; Playwright routes it to the lane server.
      await context.route("http://bap.test/**", async (route) => {
        const url = new URL(route.request().url());
        const response = await route.fetch({ url: `http://127.0.0.1:${served.port}${url.pathname}${url.search}` });
        await route.fulfill({ response });
      });
      const page = await context.newPage();
      const response = await page.goto("http://bap.test/insecure.html");
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
      assert.deepEqual(result.t11, {
        subtle: "undefined",
        cryptoKey: "undefined",
        ed25519KeyHandle: "error:invalid_key_handle",
        es256KeyHandle: "error:invalid_key_handle",
        touched: [],
      }, "T11: no crypto.subtle, no CryptoKey; both factories refuse and never touch the recording pair or options");
      assert.deepEqual(result.violations, []);
      t.diagnostic(`${name} ${browser.version()}: ${JSON.stringify(result.defaults)}; T11 ${JSON.stringify(result.t11)}`);
    } finally {
      await browser.close();
      served.server.close();
    }
  });
}
