// A dedicated worker that generates real non-extractable Ed25519 and P-256 key pairs with its own
// crypto.subtle and posts them to the page (structured clone). The page builds key handles from them
// (revision R10 / F9: keys from another realm are accepted). Served as a classic script under the
// strict CSP (worker-src falls back to script-src 'self').
async function postPairs(): Promise<void> {
  const ed = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const ec = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  (self as unknown as { postMessage(message: unknown): void }).postMessage({ ed, ec });
}
postPairs().catch((e: unknown) => (self as unknown as { postMessage(message: unknown): void }).postMessage({ error: String(e) }));
