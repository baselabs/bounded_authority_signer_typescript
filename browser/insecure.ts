// The non-secure-context lane (Chromium, http://bap.test mapped to 127.0.0.1, so the page is NOT a
// secure context and crypto.randomUUID is absent). Each report signer is called without a proofId,
// so the library's default proof id cannot be computed: the result must be a closed producer_error,
// never a thrown TypeError. With an explicit proofId the same page still signs, and the envelope
// verifies through the verifier's portable backend. Results are a measurement, never a trust decision.
import { BACKEND_ID, checkEnvelope } from "@bounded-authority-protocol/verifier";
import { signGrant, signLocalLoopbackReport, signReport, signV2Report, signV3Report } from "../src/index.js";
import { ecHandle, ecKey, edHandle, edKey } from "../test/lanes/keys.js";

const violations: string[] = [];
document.addEventListener("securitypolicyviolation", (e) => violations.push(`${e.violatedDirective} ${e.blockedURI}`));

const ISS = "https://issuer.example.test";
const AUD = "https://resource.example.test";
const INV = "550e8400-e29b-41d4-a716-446655440000";
const args = { t: "object" as const, v: new Map([["amount", { t: "int" as const, v: 5000 }]]) };
const report = (grantCompact: Uint8Array, targetUri = `${AUD}/invoke`) => ({ grantCompact, operation: "transfer", method: "POST", targetUri, invocationId: INV, castArguments: args });

async function outcome(run: () => Promise<{ ok: boolean; error?: string }>): Promise<string> {
  try {
    const r = await run();
    return r.ok ? "ok" : `error:${r.error}`;
  } catch (e) {
    return `threw:${e instanceof Error ? e.name : typeof e}`;
  }
}

async function main(): Promise<Record<string, unknown>> {
  const issuer = edKey();
  const holder = edKey();
  const g = await signGrant({ issuer: ISS, grantId: "urn:example:grant:i", audiences: [AUD], issuedAt: 1000, notBefore: 1000, expiresAt: 2000, holderThumbprint: holder.thumbprint, operations: [{ name: "transfer", selectors: [{ kind: "all" }] }] },
    edHandle(issuer, { keyId: "issuer-key", role: "issuer" }));
  if (!g.ok) throw new Error(`grant: ${g.error}`);
  const grant = g.value.grant;
  const h = edHandle(holder, { keyId: "holder-key" });
  const defaults = {
    signReport: await outcome(() => signReport(report(grant), h, { issuedAt: 1500 })),
    signLocalLoopbackReport: await outcome(() => signLocalLoopbackReport({ ...report(grant, "http://127.0.0.1:8080/invoke"), nonce: "n-1" }, h, { issuedAt: 1500 })),
    signV2Report: await outcome(() => signV2Report(report(grant), h, { issuedAt: 1500 })),
    signV3Report: await outcome(() => signV3Report(report(grant), ecHandle(ecKey(), { keyId: "holder-key" }), { issuedAt: 1500 })),
  };
  const explicit = await signReport(report(grant), h, { issuedAt: 1500, proofId: "urn:example:proof:i" });
  const verified = explicit.ok && checkEnvelope(explicit.value.grant, explicit.value.proof, {
    trustedIssuer: { keyId: "issuer-key", publicKey: issuer.publicKey }, issuer: ISS, audience: AUD, method: "POST",
    targetUri: `${AUD}/invoke`, invocationId: INV, operation: "transfer", castArguments: args,
    evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
  }).ok;
  return { backend: BACKEND_ID, secure: isSecureContext, randomUUID: typeof (crypto as { randomUUID?: unknown }).randomUUID, defaults, explicitVerifies: verified };
}

main()
  .then((result) => publish({ ...result, violations, error: null }))
  .catch((e: unknown) => publish({ backend: BACKEND_ID, secure: isSecureContext, violations, error: String(e) }));

function publish(result: Record<string, unknown>): void {
  (window as unknown as { __BAP_RESULT__: unknown }).__BAP_RESULT__ = result;
  document.getElementById("out")!.textContent = JSON.stringify(result, null, 2);
  document.body.dataset.state = "done";
}
