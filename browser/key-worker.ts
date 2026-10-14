// A dedicated worker that generates real non-extractable Ed25519 and P-256 key pairs with its own
// crypto.subtle and posts them to the page (structured clone). The page builds key handles from them
// (revision R10 / F9: keys from another realm are accepted). Served as a classic script under the
// strict CSP (worker-src falls back to script-src 'self').

// WebKit on Linux rejects about 1% of Ed25519 generateKey calls with an OperationError; retried as in
// test/lanes/webcrypto-keys.ts (three attempts in total, OperationError only); the page adds
// this worker's retry count to the lane's.
// By name, not instanceof: an iframe's DOMException is not an instance of this realm's Error.
const isOperationError = (e: unknown): boolean =>
  typeof e === "object" && e !== null && (e as { name?: unknown }).name === "OperationError";

let retries = 0;

async function generateWithRetry<T>(run: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await run();
    } catch (e) {
      if (attempt >= 3 || !isOperationError(e)) throw e;
      retries++;
    }
  }
}

async function postPairs(): Promise<void> {
  const ed = await generateWithRetry(() => crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]));
  const ec = await generateWithRetry(() => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]));
  (self as unknown as { postMessage(message: unknown): void }).postMessage({ ed, ec, retries });
}
postPairs().catch((e: unknown) => (self as unknown as { postMessage(message: unknown): void }).postMessage({ error: String(e) }));
