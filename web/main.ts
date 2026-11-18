// Live page logic for the envelope playground. Everything cryptographic runs
// through the REAL packages: this repository's signer source (the version on
// main, which can be ahead of the latest npm release) and the published
// @bounded-authority-protocol/verifier,
// bundled by esbuild for the browser. Neither package uses a Node API, and the
// verifier resolves its portable backend in the bundle, so no shim or polyfill
// is involved. No mocks, no server.
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { ed25519KeyHandle, es256KeyHandle, signGrant, signReport, signV2Grant, signV2Report, signV3Grant, signV3Report, type KeyHandle } from "../src/index.js";
import { base64urlEncode, checkEnvelope, thumbprint, utf8Str, v2, v3 } from "@bounded-authority-protocol/verifier";

// ---------- keys: browser custody, never inside the library ----------

interface CustodyKey {
  pub: Uint8Array;
  handle: KeyHandle;
  mode: "WebCrypto non-extractable" | "in-page (noble)";
}
let major: 1 | 2 | 3 = 1;
async function makeKey(keyId: string, role: "issuer" | "holder"): Promise<CustodyKey> {
  const suite = major;
  const custody = (document.getElementById("custody") as HTMLSelectElement).value;
  if (custody === "webcrypto") {
    const algorithm = suite === 3 ? { name: "ECDSA", namedCurve: "P-256" } : { name: "Ed25519" };
    let pair: CryptoKeyPair | undefined;
    for (let attempt = 0; attempt < 5; attempt++) {
      try { pair = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]) as CryptoKeyPair; break; }
      catch (error) { if (!(error instanceof DOMException) || error.name !== "OperationError" || attempt === 4) throw error; }
    }
    if (!pair) throw new Error("key generation failed");
    const made = suite === 3 ? await es256KeyHandle(pair, { keyId, role }) : await ed25519KeyHandle(pair, { keyId, role });
    if (!made.ok) throw new Error(made.error);
    return { pub: await made.value.publicKey(), handle: made.value, mode: "WebCrypto non-extractable" };
  }
  const kp = suite === 3 ? p256.keygen() : ed25519.keygen();
  const pub = suite === 3 ? p256.Point.fromBytes(kp.publicKey).toBytes(false) : kp.publicKey;
  const print = suite === 3 ? v3.thumbprint({ kty: "EC", crv: "P-256", x: b64(pub.subarray(1, 33)), y: b64(pub.subarray(33)) }) : jwkThumb(pub);
  return { pub, mode: "in-page (noble)", handle: {
    sign: async (message) => suite === 3 ? p256.sign(message, kp.secretKey, { prehash: true, lowS: false, format: "compact" }) : ed25519.sign(message, kp.secretKey),
    publicKey: () => pub, thumbprint: () => print,
    keyIdentity: () => ({ keyId, publicKey: pub }), signingIdentity: () => ({ role, keyId, publicKey: pub }),
  } };
}
const grantSigner = () => major === 3 ? signV3Grant : major === 2 ? signV2Grant : signGrant;
const reportSigner = () => major === 3 ? signV3Report : major === 2 ? signV2Report : signReport;

const b64 = (b: Uint8Array): string => utf8Str(base64urlEncode(b));
const utf8 = new TextDecoder();
// Lenient display decode of a (possibly tampered) base64url segment: characters
// outside the alphabet are dropped and a dangling character carries no byte.
function fromBase64url(segment: string): Uint8Array {
  const clean = segment.replace(/[^A-Za-z0-9_-]/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const whole = clean.length % 4 === 1 ? clean.slice(0, -1) : clean;
  return Uint8Array.from(atob(whole + "=".repeat((4 - (whole.length % 4)) % 4)), (c) => c.charCodeAt(0));
}
const jwkThumb = (pub: Uint8Array): string => thumbprint({ kty: "OKP", crv: "Ed25519", x: b64(pub) });

// The demo's fixed scenario: a holder may read one selected record. The
// timestamps match the package's own oracle test, so every value on screen is
// deterministic and inspectable.
const SCENE = {
  issuer: "https://issuer.example.test",
  audience: "https://resource.example.test",
  targetUri: "https://resource.example.test/invoke",
  invocationId: "550e8400-e29b-41d4-a716-446655440000",
  grantId: "urn:demo:grant:1",
  proofId: "urn:demo:proof:1",
  issuedAt: 1000, notBefore: 1000, expiresAt: 2000, evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300,
};
const castArguments = (): { t: "object"; v: Map<string, { t: "int"; v: number }> } => ({
  t: "object", v: new Map([["record", { t: "int", v: 90112 }]]),
});

interface Actor { key: CustodyKey; thumb: string; keyId: string }
let issuer: Actor, holder: Actor, impostor: Actor;
let grantCompact: Uint8Array | null = null;
let proofCompact: Uint8Array | null = null;
let tamperedProof: Uint8Array | null = null;

const handle = (a: Actor, extra: Partial<KeyHandle> = {}): KeyHandle => ({ ...a.key.handle, ...extra });

// ---------- state + DOM ----------

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => document.getElementById(id) as T;
const bGrant = $<HTMLButtonElement>("btn-grant"), bProof = $<HTMLButtonElement>("btn-proof"), bVerify = $<HTMLButtonElement>("btn-verify");
const tamperBtns = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-tamper]"));

function flash(lane: HTMLElement): void {
  lane.classList.remove("flash");
  void lane.offsetWidth; // restart the animation
  lane.classList.add("flash");
}

function setChip(el: HTMLElement, a: Actor, roleNote: string): void {
  el.innerHTML = `<b><svg class="ic"><use href="#i-key"/></svg> ${a.keyId}</b>
    <span class="thumb">jkt ${a.thumb.slice(0, 10)}…</span><span>${roleNote} · ${a.key.mode}</span>`;
}

function artifactCard(kind: "grant" | "proof", typ: string, extra: string, onPick: () => void): HTMLButtonElement {
  const card = document.createElement("button");
  card.className = `artifact-card ${kind}`;
  card.innerHTML = `<span class="t"><svg class="ic"><use href="#i-doc"/></svg> ${kind.toUpperCase()}</span>
    <span class="meta">typ: ${typ} · ${extra}</span>`;
  card.addEventListener("click", onPick);
  return card;
}

// ---------- wire viewer ----------

const wireBody = $("wire-body"), segTabs = $("seg-tabs");
let currentBytes: { label: string; compact: Uint8Array } | null = null;
let highlight: { seg: number; from: number; to: number } | null = null;
let lastTamper: string | null = null;

function showWire(label: string, compact: Uint8Array, hl?: { seg: number; from: number; to: number }): void {
  currentBytes = { label, compact };
  highlight = hl ?? null;
  document.querySelectorAll(".artifact-card.selected").forEach((c) => c.classList.remove("selected"));
  const text = utf8.decode(compact);
  const segs = text.split(".");
  segTabs.innerHTML = "";
  const names = ["protected (header)", "payload", "signature"];
  segs.forEach((s, i) => {
    const b = document.createElement("button");
    b.textContent = names[i] ?? `segment ${i}`;
    if (i === (highlight?.seg ?? 0)) b.classList.add("on");
    b.addEventListener("click", () => renderSeg(segs, i, names[i] ?? `segment ${i}`));
    segTabs.appendChild(b);
  });
  renderSeg(segs, highlight?.seg ?? 0, names[highlight?.seg ?? 0] ?? "segment");
}

function renderSeg(segs: string[], idx: number, name: string): void {
  Array.from(segTabs.children).forEach((c, i) => c.classList.toggle("on", i === idx));
  const raw = fromBase64url(segs[idx] ?? "");
  let body: string;
  if (idx === 2) {
    body = Array.from(raw, (b) => b.toString(16).padStart(2, "0")).join("");
  } else {
    const decoded = utf8.decode(raw);
    try { body = JSON.stringify(JSON.parse(decoded), null, 2); } catch { body = decoded; }
  }
  wireBody.innerHTML = `<span class="k">// Showing ${name} for ${currentBytes?.label ?? ""} (${raw.length} bytes).\n</span>`;
  if (highlight && highlight.seg === idx) {
    const lines = body.split("\n");
    const lineNo = Math.min(highlight.from, lines.length - 1);
    wireBody.append(lines.slice(0, lineNo).join("\n") + "\n");
    const mark = document.createElement("span");
    mark.className = "hl";
    mark.textContent = "◀◀ " + lines[lineNo];
    wireBody.append(mark);
    wireBody.append("\n" + lines.slice(lineNo + 1).join("\n"));
  } else {
    wireBody.append(body);
  }
}

// ---------- the three actions (real package calls) ----------

async function doGrant(): Promise<void> {
  const r = await grantSigner()({
    issuer: SCENE.issuer, grantId: SCENE.grantId, audiences: [SCENE.audience],
    issuedAt: SCENE.issuedAt, notBefore: SCENE.notBefore, expiresAt: SCENE.expiresAt,
    holderThumbprint: holder.thumb,
    operations: [{ name: "read_record", selectors: [{ kind: "equals", path: ["record"], value: { t: "int", v: 90112 } }] }],
  }, handle(issuer, { signingIdentity: () => ({ role: "issuer", keyId: issuer.keyId, publicKey: issuer.key.pub }) }));
  if (!r.ok) { setVerdict("fail", `signGrant → ${r.error}`); return; }
  grantCompact = r.value.grant;
  proofCompact = tamperedProof = null;
  bVerify.disabled = true;
  $("slot-proof").textContent = "";
  $("facts-body").textContent = "—";
  $("flow-proof").classList.remove("arrived");
  const slot = $("slot-grant");
  slot.textContent = "";
  const card = artifactCard("grant", "ba+cap", `jkt ${holder.thumb.slice(0, 8)}…`, () => { mark(card); showWire("grant", grantCompact!); });
  slot.appendChild(card);
  $("flow-grant").classList.add("arrived");
  flash($("lane-issuer"));
  bProof.disabled = false;
  tamperBtns.forEach((b) => (b.disabled = true));
  setVerdict("idle", "Grant signed. The holder can now prove a request.");
}

async function doProof(): Promise<void> {
  if (!grantCompact) return;
  const r = await reportSigner()({
    grantCompact, operation: "read_record", method: "POST", targetUri: SCENE.targetUri,
    invocationId: SCENE.invocationId, castArguments: castArguments(),
  }, handle(holder), { issuedAt: SCENE.evaluationTime, proofId: SCENE.proofId });
  if (!r.ok) { setVerdict("fail", `signReport → ${r.error}`); return; }
  proofCompact = r.value.proof;
  tamperedProof = null;
  const slot = $("slot-proof");
  slot.textContent = "";
  const card = artifactCard("proof", "dpop+jwt", "POST /invoke · record 90112", () => { mark(card); showWire("proof", proofCompact!); });
  slot.appendChild(card);
  card.id = "proof-card";
  $("flow-proof").classList.add("arrived");
  flash($("lane-holder"));
  bVerify.disabled = false;
  tamperBtns.forEach((b) => (b.disabled = false));
  setVerdict("idle", "Envelope assembled. Verify it to inspect the facts.");
}

function mark(card: HTMLElement): void {
  document.querySelectorAll(".artifact-card.selected").forEach((c) => c.classList.remove("selected"));
  card.classList.add("selected");
}

function expected(over: Record<string, unknown> = {}) {
  return {
    trustedIssuer: { keyId: issuer.keyId, publicKey: issuer.key.pub },
    issuer: SCENE.issuer, audience: SCENE.audience,
    method: "POST", targetUri: SCENE.targetUri, invocationId: SCENE.invocationId,
    operation: "read_record", castArguments: castArguments(),
    evaluationTime: SCENE.evaluationTime, clockSkew: SCENE.clockSkew, proofMaxAge: SCENE.proofMaxAge,
    nonce: { kind: "not_required" as const },
    ...over,
  };
}

function verifyWith(grant: Uint8Array, proof: Uint8Array, exp: ReturnType<typeof expected>): void {
  const verify = major === 3 ? v3.checkEnvelope : major === 2 ? v2.checkEnvelope : checkEnvelope;
  const at = verify(grant, proof, exp as never);
  if (at.ok) {
    setVerdict("ok", "ENVELOPE OK: cryptographic facts returned");
    $("facts-body").innerHTML = rawJsonBox(at.value);
    $("tamper-hint").className = "hint";
    $("tamper-hint").textContent = "Change an input below to see a real, closed INVALID from the verifier.";
    return;
  }
  const why: Record<string, string> = {
    payload: "Request-digest binding: the proof commits to the digest of this request",
    operation: "Operation match: the grant and proof bind one operation",
    expiry: "Time validity: grants and proofs expire",
    impostor: "Holder binding: the grant names one holder key (jkt), but another signed this proof",
    issuer: "Issuer trust: the verifier was told to trust a different issuer key",
  };
  if (!at.ok) {
    setVerdict("fail", "VERIFICATION FAILED: <b>INVALID</b>");
    $("facts-body").innerHTML = rawJsonBox(at);
    const which = lastTamper ? why[lastTamper] : undefined;
    $("tamper-hint").className = "hint fail";
    $("tamper-hint").textContent = which
      ? `${which}. The verifier returned exactly {"ok":false}, without a reason or partial facts. Verification is not authorization.`
      : 'The verifier returned exactly {"ok":false}, without a reason or partial facts. Verification is not authorization.';
  }
}


// ---------- artifact accordions: designed, animated disclosure ----------
const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");


// The FACTS area displays raw JSON without syntax formatting.
// Strings containing control or lossy characters use defensive hex encoding.
function sanitize(v: unknown): unknown {
  // Byte arrays render as their base64url wire form. JSON.stringify on a
  // Uint8Array explodes into {"0":123,"1":34,…} index objects otherwise.
  if (v instanceof Uint8Array) {
    return b64(v);
  }
  if (typeof v === "string" && /[\u0000-\u0008\u000e-\u001f\u007f-\u00ff\ufffd]/.test(v)) {
    return "0x" + Array.from(v, (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  }
  if (Array.isArray(v)) return v.map(sanitize);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) o[k] = sanitize(val);
    return o;
  }
  return v;
}
function rawJsonBox(facts: unknown): string {
  return `<pre class="codebox">${esc(JSON.stringify(sanitize(facts), null, 2))}</pre>`;
}

// One delegated listener drives every accordion on the page, including ones
// injected later (artifacts after mint).
document.addEventListener("click", (e) => {
  const head = (e.target as HTMLElement).closest?.(".acc-head");
  if (!(head instanceof HTMLElement)) return;
  const acc = head.parentElement;
  if (!acc) return;
  const open = acc.classList.toggle("open");
  head.setAttribute("aria-expanded", String(open));
});

function setVerdict(state: "idle" | "ok" | "fail", html: string): void {
  const v = $("verdict");
  v.dataset.state = state;
  const icon = state === "ok" ? "#i-check" : state === "fail" ? "#i-x" : "#i-terminal";
  v.innerHTML = `<span class="verdict-mark"><svg class="ic"><use href="${icon}"/></svg></span><span class="verdict-text">${html}</span>`;
  if (state !== "idle") flash($("lane-verifier"));
}

function doVerify(): void {
  if (!grantCompact || !proofCompact) return;
  verifyWith(grantCompact, proofCompact, expected());
  showWire("proof (as verified)", proofCompact);
}

// ---------- the tamper deck ----------

async function tamper(kind: string): Promise<void> {
  if (!grantCompact || !proofCompact) return;
  lastTamper = kind;
  const proofCard = $("proof-card");
  switch (kind) {
    case "payload": {
      // Request substitution: the proof commits to the request digest, so the
      // attacker leaves the proof untouched and rewrites the REQUEST instead
      // (record 90112 → 90113). The verifier's request-digest binding must reject.
      tamperedProof = proofCompact;
      verifyWith(grantCompact, tamperedProof, expected({
        castArguments: { t: "object", v: new Map([["record", { t: "int", v: 90113 }]]) },
      }));
      showWire("Unchanged proof; modified request", proofCompact);
      return;
    }
    case "operation":
      verifyWith(grantCompact, proofCompact, expected({ operation: "delete_record" }));
      showWire("proof (unchanged)", proofCompact);
      return;
    case "expiry":
      verifyWith(grantCompact, proofCompact, expected({ evaluationTime: 2600 }));
      showWire("proof (unchanged)", proofCompact);
      return;
    case "impostor": {
      // A second holder key signs a valid proof over the stolen grant.
      // The grant binds the ORIGINAL holder's thumbprint. Identity fails.
      const r = await reportSigner()({
        grantCompact, operation: "read_record", method: "POST", targetUri: SCENE.targetUri,
        invocationId: SCENE.invocationId, castArguments: castArguments(),
      }, handle(impostor), { issuedAt: SCENE.evaluationTime, proofId: "urn:demo:proof:stolen" });
      if (!r.ok) { setVerdict("fail", `signReport → ${r.error}`); return; }
      tamperedProof = r.value.proof;
      showWire("impostor proof", tamperedProof);
      break;
    }
    case "issuer":
      verifyWith(grantCompact, proofCompact, expected({ trustedIssuer: { keyId: issuer.keyId, publicKey: impostor.key.pub } }));
      showWire("proof (unchanged)", proofCompact);
      return;
  }
  if (tamperedProof) {
    if (proofCard) { proofCard.classList.add("tampered"); mark(proofCard); }
    verifyWith(grantCompact, tamperedProof, expected());
  }
}

// ---------- boot ----------

async function reset(): Promise<void> {
  document.body.dataset.ready = "false";
  bGrant.disabled = true; bProof.disabled = true; bVerify.disabled = true;
  for (const id of ["contract-major", "custody", "reset", "selector-refusal"]) ($<HTMLButtonElement | HTMLSelectElement>(id)).disabled = true;
  $("selector-result").textContent = "";
  major = Number(($<HTMLSelectElement>("contract-major")).value) as 1 | 2 | 3;
  const actor = async (keyId: string, role: "issuer" | "holder"): Promise<Actor> => {
    const key = await makeKey(keyId, role); return { key, keyId, thumb: await key.handle.thumbprint() };
  };
  [issuer, holder, impostor] = await Promise.all([
    actor("issuer-key", "issuer"),
    actor("holder-key", "holder"),
    actor("impostor-key", "holder"),
  ]);
  grantCompact = proofCompact = tamperedProof = null;
  lastTamper = null; currentBytes = null; highlight = null;
  setChip($("chip-issuer"), issuer, "issuer role");
  setChip($("chip-holder"), holder, "your key");
  $("trust-key").textContent = `${issuer.keyId} · jkt ${issuer.thumb.slice(0, 8)}…`;
  $("custody-mode").textContent = `key custody: ${holder.key.mode}`;
  for (const id of ["slot-grant", "slot-proof"]) { $(id).textContent = ""; }
  for (const id of ["flow-grant", "flow-proof"]) { $(id).classList.remove("arrived"); }
  bProof.disabled = true; bVerify.disabled = true;
  tamperBtns.forEach((b) => (b.disabled = true));
  $("facts-body").textContent = "—";
  $("tamper-hint").className = "hint";
  $("tamper-hint").textContent = "Sign and prove first. Then try changing the inputs.";
  segTabs.innerHTML = "";
  wireBody.textContent = "nothing selected yet";
  setVerdict("idle", "verify an envelope to see the fact sheet");
  bGrant.disabled = false;
  for (const id of ["contract-major", "custody", "reset", "selector-refusal"]) ($<HTMLButtonElement | HTMLSelectElement>(id)).disabled = false;
  document.body.dataset.ready = "true";
}

bGrant.addEventListener("click", doGrant);
bProof.addEventListener("click", doProof);
bVerify.addEventListener("click", doVerify);
$("reset").addEventListener("click", reset);
tamperBtns.forEach((b) => b.addEventListener("click", () => void tamper(b.dataset.tamper!)));

for (const id of ["contract-major", "custody"]) $(id).addEventListener("change", () => void reset());
$("selector-refusal").addEventListener("click", async () => {
  const refused = await grantSigner()({ issuer: SCENE.issuer, grantId: SCENE.grantId, audiences: [SCENE.audience],
    issuedAt: SCENE.issuedAt, notBefore: SCENE.notBefore, expiresAt: SCENE.expiresAt, holderThumbprint: holder.thumb,
    operations: [{ name: "read_record", selectors: [{ kind: "equals", path: ["record"], value: { t: "float", v: 90112 } }] }] }, handle(issuer));
  $("selector-result").textContent = refused.ok ? "unexpected acceptance" : refused.error;
});
void reset().catch((error: unknown) => { setVerdict("fail", String(error)); document.body.dataset.ready = "error"; });
