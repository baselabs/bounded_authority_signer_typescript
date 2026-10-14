// The runtime lane entry for Node, Deno and Bun: asserts the verifier's resolved BACKEND_ID first (a lane
// that resolves the wrong backend runs nothing), then runs the L2/L3 battery and prints one JSON report
// on stdout, followed by the WebCrypto key-handle battery (test/lanes/webcrypto.ts) with real engine keys.
// Exit status 0 only if the backend matches --expect and every check holds.
//   node --import tsx/esm test/lanes/runtime.ts --expect=node
//   node --conditions=bap-portable --import tsx/esm test/lanes/runtime.ts --expect=portable
//   deno run --sloppy-imports --allow-read --allow-env test/lanes/runtime.ts --expect=portable
//   bun test/lanes/runtime.ts --expect=portable
import { BACKEND_ID } from "@bounded-authority-protocol/verifier";
import { runL2 } from "./l2.js";
import { runWebCryptoLane } from "./webcrypto.js";
import { edPair } from "./webcrypto-keys.js";

declare const Deno: { version: { deno: string }; args: string[]; exit(code: number): never } | undefined;
declare const Bun: { version: string } | undefined;

const runtime = typeof Deno !== "undefined" ? `deno ${Deno.version.deno}` : typeof Bun !== "undefined" ? `bun ${Bun.version}` : `node ${process.version}`;
const args = typeof Deno !== "undefined" ? Deno.args : process.argv.slice(2);
const expect = args.find((a) => a.startsWith("--expect="))?.slice("--expect=".length);
const exit = (code: number): never => (typeof Deno !== "undefined" ? Deno.exit(code) : process.exit(code));

if (expect !== "node" && expect !== "portable") {
  console.error("runtime lane: pass --expect=node or --expect=portable");
  exit(2);
}
if (BACKEND_ID !== expect) {
  console.error(`runtime lane (${runtime}): BACKEND_ID is "${BACKEND_ID}", this lane expects "${expect}"; no check was run`);
  exit(1);
}
const start = performance.now();
const report = await runL2({ secure: true });
const webcrypto = await runWebCryptoLane();
// Revision R3: whether code in this process can export a NON-extractable private key through
// node:crypto's KeyObject.from() (Node and Bun can; Deno refuses). Recorded, and asserted per lane.
let keyObjectExport: string;
try {
  const { KeyObject } = await import("node:crypto");
  const pair = await edPair(false);
  const jwk = KeyObject.from(pair.privateKey as never).export({ format: "jwk" }) as { d?: unknown };
  keyObjectExport = typeof jwk.d === "string" ? "exported" : "no private member";
} catch (e) {
  keyObjectExport = `refused:${e instanceof Error ? e.name : typeof e}`;
}
const ok = Object.values(report.checks).every(Boolean) && Object.values(webcrypto.checks).every(Boolean);
console.log(JSON.stringify({ runtime, backend: BACKEND_ID, ok, ms: Math.round(performance.now() - start), ...report, webcrypto, keyObjectExport }));
exit(ok ? 0 : 1);
