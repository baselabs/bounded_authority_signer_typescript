// The envelope playground — the live page logic. Everything cryptographic runs
// through the REAL packages: this repository's signer source (byte-identical to
// the published 0.1.2) and the published @bounded-authority-protocol/verifier,
// bundled by esbuild with a node:crypto shim over @noble. No mocks, no server.
import { keygen, sign as nobleSign } from "@noble/ed25519";
import { signGrant, signReport, type KeyHandle } from "../src/index.js";
import { checkEnvelope, thumbprint } from "@bounded-authority-protocol/verifier";

// ---------- keys: browser custody, never inside the library ----------

interface CustodyKey {
  pub: Uint8Array;
  sign: (m: Uint8Array) => Promise<Uint8Array>;
  mode: "WebCrypto non-extractable" | "in-page (noble)";
}

async function makeKey(): Promise<CustodyKey> {
  try {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" } as Algorithm, false, ["sign"])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    return {
      pub: new Uint8Array(raw),
      sign: async (m) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, m as BufferSource)),
      mode: "WebCrypto non-extractable",
    };
  } catch {
    // Ed25519 WebCrypto unavailable in this browser — an in-page noble key keeps
    // the same boundary: the private bytes live only in this closure.
    const kp = keygen();
    return {
      pub: new Uint8Array(kp.publicKey),
      sign: async (m) => nobleSign(m, kp.secretKey),
      mode: "in-page (noble)",
    };
  }
}

const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
const jwkThumb = (pub: Uint8Array): string => thumbprint({ kty: "OKP", crv: "Ed25519", x: b64(pub) });

// The demo's fixed scenario (mirrors the package's own oracle test, so every
// timestamp on screen is deterministic and inspectable).
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
  t: "object", v: new Map([["amount", { t: "int", v: 5000 }]]),
});

interface Actor { key: CustodyKey; thumb: string; keyId: string }
let issuer: Actor, holder: Actor, impostor: Actor;
let grantCompact: Uint8Array | null = null;
let proofCompact: Uint8Array | null = null;
let tamperedProof: Uint8Array | null = null;

const handle = (a: Actor, extra: Partial<KeyHandle> = {}): KeyHandle => ({
  sign: (m) => a.key.sign(m),
  publicKey: () => a.key.pub,
  thumbprint: () => a.thumb,
  keyIdentity: () => ({ keyId: a.keyId, publicKey: a.key.pub }),
  ...extra,
});

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
  const text = Buffer.from(compact).toString("utf8");
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
  const raw = Buffer.from(segs[idx], "base64url");
  let body: string;
  if (idx === 2) {
    body = Array.from(raw, (b) => b.toString(16).padStart(2, "0")).join("");
  } else {
    const utf8 = raw.toString("utf8");
    try { body = JSON.stringify(JSON.parse(utf8), null, 2); } catch { body = utf8; }
  }
  wireBody.innerHTML = `<span class="k">// ${currentBytes?.label ?? ""} — ${name} (${raw.length} bytes)\n</span>`;
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
  const r = await signGrant({
    issuer: SCENE.issuer, grantId: SCENE.grantId, audiences: [SCENE.audience],
    issuedAt: SCENE.issuedAt, notBefore: SCENE.notBefore, expiresAt: SCENE.expiresAt,
    holderThumbprint: holder.thumb,
    operations: [{ name: "transfer", selectors: [{ kind: "all" } as never] }],
  }, handle(issuer, { signingIdentity: () => ({ role: "issuer", keyId: issuer.keyId, publicKey: issuer.key.pub }) }));
  if (!r.ok) { setVerdict("fail", `signGrant → ${r.error}`); return; }
  grantCompact = r.value.grant;
  tamperedProof = null;
  const slot = $("slot-grant");
  slot.textContent = "";
  const card = artifactCard("grant", "ba+grant", `jkt ${holder.thumb.slice(0, 8)}…`, () => { mark(card); showWire("grant", grantCompact!); });
  slot.appendChild(card);
  $("flow-grant").classList.add("arrived");
  flash($("lane-issuer"));
  bProof.disabled = false;
  tamperBtns.forEach((b) => (b.disabled = true));
  setVerdict("idle", "grant signed — the holder can now prove a request");
}

async function doProof(): Promise<void> {
  if (!grantCompact) return;
  const r = await signReport({
    grantCompact, operation: "transfer", method: "POST", targetUri: SCENE.targetUri,
    invocationId: SCENE.invocationId, castArguments: castArguments(),
  }, handle(holder), { issuedAt: SCENE.evaluationTime, proofId: SCENE.proofId });
  if (!r.ok) { setVerdict("fail", `signReport → ${r.error}`); return; }
  proofCompact = r.value.proof;
  tamperedProof = null;
  const slot = $("slot-proof");
  slot.textContent = "";
  const card = artifactCard("proof", "dpop+jwt", "POST /invoke · amount 5000", () => { mark(card); showWire("proof", proofCompact!); });
  slot.appendChild(card);
  card.id = "proof-card";
  $("flow-proof").classList.add("arrived");
  flash($("lane-holder"));
  bVerify.disabled = false;
  tamperBtns.forEach((b) => (b.disabled = false));
  setVerdict("idle", "envelope assembled — verify it");
}

function mark(card: HTMLElement): void {
  document.querySelectorAll(".artifact-card.selected").forEach((c) => c.classList.remove("selected"));
  card.classList.add("selected");
}

// Fact-sheet rendering: Maps become objects, byte arrays become hex — anything
// byte-like (Uint8Array or the Buffer polyfill) collapses to a readable digest.
function factsReplacer(_k: string, v: unknown): unknown {
  if (v instanceof Map) return Object.fromEntries(v);
  if (v instanceof Uint8Array) return `hex:${Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32)}…`;
  return v;
}

function expected(over: Record<string, unknown> = {}) {
  return {
    trustedIssuer: { keyId: issuer.keyId, publicKey: issuer.key.pub },
    issuer: SCENE.issuer, audience: SCENE.audience,
    method: "POST", targetUri: SCENE.targetUri, invocationId: SCENE.invocationId,
    operation: "transfer", castArguments: castArguments(),
    evaluationTime: SCENE.evaluationTime, clockSkew: SCENE.clockSkew, proofMaxAge: SCENE.proofMaxAge,
    nonce: { kind: "not_required" as const },
    ...over,
  };
}

function verifyWith(grant: Uint8Array, proof: Uint8Array, exp: ReturnType<typeof expected>): void {
  const at = checkEnvelope(grant, proof, exp as never);
  if (at.ok) {
    setVerdict("ok", "ENVELOPE OK — cryptographic facts returned");
    $("facts-body").innerHTML = factPanel("envelope facts", at.value);
    $("tamper-hint").className = "hint";
    $("tamper-hint").textContent = "Now break it — every button below produces a real, closed INVALID from the verifier.";
    return;
  }
  const why: Record<string, string> = {
    payload: "request-digest binding — the proof commits to the digest of THIS request",
    operation: "operation match — the grant and proof bind one operation",
    expiry: "time window — grants and proofs expire",
    impostor: "holder binding — the grant names one holder key (jkt), and this proof was signed by another",
    issuer: "issuer trust — the verifier was told to trust a different issuer key",
  };
  if (!at.ok) {
    setVerdict("fail", "VERIFICATION FAILED — <b>INVALID</b>");
    $("facts-body").innerHTML = factPanel("result", at);
    const which = lastTamper ? why[lastTamper] : undefined;
    $("tamper-hint").className = "hint fail";
    $("tamper-hint").textContent = which
      ? `${which} — and the verifier returned exactly {"ok":false}. No reason, no partial: verification is not authority, and there is no oracle for an attacker.`
      : 'the verifier returned exactly {"ok":false} — no reason, no partial (verification is not authority).';
  }
}


// ---------- fact panels (designed key/value view; raw JSON behind a toggle) ----------
const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// Byte-ish values (Uint8Array, or strings carrying raw binary from the
// package's decode surface) render as compact hex — never utf-8 mojibake.
const toHex = (bytes: number[]): string => bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
const isBinaryString = (s: string): boolean => /[\u0000-\u0008\u000e-\u001f\u007f-\u00ff]/.test(s);
const asBytes = (v: Uint8Array | string): number[] =>
  typeof v === "string" ? Array.from(v, (c) => c.charCodeAt(0) & 0xff) : Array.from(v);

function renderValue(v: unknown): { shown: string; title: string } | null {
  if (v instanceof Uint8Array || (typeof v === "string" && isBinaryString(v))) {
    const bytes = asBytes(v as Uint8Array | string);
    const hex = toHex(bytes);
    return { shown: `hex:${hex.slice(0, 24)}… (${bytes.length}B)`, title: hex };
  }
  return null;
}

function factRows(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    const s = String(obj);
    return `<span class="fv">${esc(s)}</span>`;
  }
  const entries: [string, unknown][] = Array.isArray(obj)
    ? obj.map((v, i) => [`#${i + 1}`, v])
    : Object.entries(obj as Record<string, unknown>);
  return entries.map(([k, v]) => {
    if (v !== null && typeof v === "object" && !(v instanceof Uint8Array)) {
      return `<div class="factrow nest"><span class="fk">${esc(k)}</span><div class="subfacts">${factRows(v)}</div></div>`;
    }
    const bin = renderValue(v);
    if (bin) {
      return `<div class="factrow"><span class="fk">${esc(k)}</span><span class="fv" title="${esc(bin.title)}">${esc(bin.shown)}</span></div>`;
    }
    const s = String(v);
    const shown = s.length > 64 ? s.slice(0, 64) + "…" : s;
    return `<div class="factrow"><span class="fk">${esc(k)}</span><span class="fv" title="${esc(s)}">${esc(shown)}</span></div>`;
  }).join("");
}

function factPanel(label: string, facts: unknown): string {
  return `<div class="factlabel">${esc(label)}</div><div class="facts">${factRows(facts)}</div>`;
}

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
      // The replay attack: the proof commits to a DIGEST of the request, so the
      // attacker leaves the proof untouched and rewrites the REQUEST instead
      // (amount 5000 → 9000). The verifier's request-digest binding must reject.
      tamperedProof = proofCompact;
      verifyWith(grantCompact, tamperedProof, expected({
        castArguments: { t: "object", v: new Map([["amount", { t: "int", v: 9000 }]]) },
      }));
      showWire("proof (byte-identical — the REQUEST changed)", proofCompact);
      return;
    }
    case "operation":
      verifyWith(grantCompact, proofCompact, expected({ operation: "withdraw" }));
      showWire("proof (unchanged)", proofCompact);
      return;
    case "expiry":
      verifyWith(grantCompact, proofCompact, expected({ evaluationTime: 2600 }));
      showWire("proof (unchanged)", proofCompact);
      return;
    case "impostor": {
      // A second holder key signs a perfectly valid proof over the stolen grant —
      // but the grant binds the ORIGINAL holder's thumbprint. Identity fails.
      const r = await signReport({
        grantCompact, operation: "transfer", method: "POST", targetUri: SCENE.targetUri,
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
  [issuer, holder, impostor] = await Promise.all([
    (async () => { const k = await makeKey(); return { key: k, thumb: jwkThumb(k.pub), keyId: "issuer-key" }; })(),
    (async () => { const k = await makeKey(); return { key: k, thumb: jwkThumb(k.pub), keyId: "holder-key" }; })(),
    (async () => { const k = await makeKey(); return { key: k, thumb: jwkThumb(k.pub), keyId: "impostor-key" }; })(),
  ]);
  grantCompact = proofCompact = tamperedProof = null;
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
  $("tamper-hint").textContent = "Sign and prove first — then break it on purpose.";
  segTabs.innerHTML = "";
  wireBody.textContent = "nothing selected yet";
  setVerdict("idle", "verify an envelope to see the fact sheet");
}

bGrant.addEventListener("click", doGrant);
bProof.addEventListener("click", doProof);
bVerify.addEventListener("click", doVerify);
$("reset").addEventListener("click", reset);
tamperBtns.forEach((b) => b.addEventListener("click", () => void tamper(b.dataset.tamper!)));

void reset();
