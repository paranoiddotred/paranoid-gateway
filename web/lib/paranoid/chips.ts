// The gateway's side of sealing questions to the chip (lib/paranoid/sealchip.ts). It looks up which
// Chutes TEE instances can take sealed requests, hands one instance key and one single-use invoke
// nonce to each browser, and passes the sealed bytes to Chutes. It never holds a key that opens them.
import type { Model } from "./server.ts";
import { sealToChip } from "./sealchip.ts";

const API = "https://api.chutes.ai";
export const CHUTES_HOST = "llm.chutes.ai";

type Slot = { instance: string; key: string; nonce: string };
type Pool = { slots: Slot[]; expiresAt: number; fetchedAt: number };
const g = globalThis as unknown as { __chuteIds?: Map<string, string | null>; __chipPools?: Map<string, Pool>; __chipWait?: Map<string, { ms: number; at: number }> };
const chuteIds = (g.__chuteIds ??= new Map());
const pools = (g.__chipPools ??= new Map());
// How long each chip took to start answering lately. Chutes routes plain requests to a quiet chip by
// itself; a sealed request names its chip, so the gateway steers new questions to the quick ones.
const waits = (g.__chipWait ??= new Map());
const UNTRIED = 3_000; // a chip nobody has asked lately is tried before one known to be slower than this
const STALE = 5 * 60_000; // a chip's speed is forgotten after five minutes, so a busy chip gets tried again
const BUSY = 10_000; // when even the quickest chip took longer than this lately, questions go the usual way
const waitOf = (instance: string) => { const w = waits.get(instance); return w && Date.now() - w.at < STALE ? w.ms : UNTRIED; };
const noteWait = (instance: string, ms: number) => {
  const w = waits.get(instance);
  waits.set(instance, { ms: w && Date.now() - w.at < STALE ? (w.ms + ms) / 2 : ms, at: Date.now() });
};

/** The Chutes chute behind a model, or null when the model is not on a TEE chute. */
export async function chuteOf(model: Model): Promise<string | null> {
  if (new URL(model.url).host !== CHUTES_HOST) return null;
  if (chuteIds.has(model.name)) return chuteIds.get(model.name)!;
  const r = await fetch(`${API}/chutes/${encodeURIComponent(model.name)}`, { headers: { authorization: `Bearer ${model.key}` }, signal: AbortSignal.timeout(10_000) });
  if (!r.ok) return null; // not cached: a hiccup should not switch sealing off for good
  const j = (await r.json()) as { chute_id?: string; tee?: boolean };
  const id = j.tee && j.chute_id ? j.chute_id : null;
  chuteIds.set(model.name, id);
  return id;
}

const gr = globalThis as unknown as { __running?: Map<string, { at: number; up: boolean }>; __served?: { at: number; ids: Promise<Set<string>> }; __sees?: Map<string, boolean> };
// Which served models take photos, from the same list ("image" among their input modalities).
const sees = (gr.__sees ??= new Map());
const running = (gr.__running ??= new Map());
/** The models Chutes serves right now by name, from its OpenAI-style list (refreshed every two minutes). */
function served(key: string): Promise<Set<string>> {
  if (gr.__served && Date.now() - gr.__served.at < 120_000) return gr.__served.ids;
  const ids = fetch(`https://${CHUTES_HOST}/v1/models`, { headers: { authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(8_000) })
    .then(async (r) => {
      if (!r.ok) throw new Error(String(r.status));
      const list = ((await r.json()) as { data: { id: string; input_modalities?: string[] }[] }).data;
      for (const m of list) sees.set(m.id, !!m.input_modalities?.includes("image"));
      return new Set(list.map((m) => m.id));
    });
  gr.__served = { at: Date.now(), ids };
  ids.catch(() => { gr.__served = undefined; });
  return ids;
}
/** Whether Chutes has the model running: it is on Chutes' list of served models, or its own chute has
 *  at least one active instance (some chutes answer without being listed). Checked at most every two
 *  minutes, so a model Chutes brings back is offered again by itself. Models not on Chutes count as
 *  running, and a failed check keeps the last answer. */
export async function isRunning(model: Model): Promise<boolean> {
  if (new URL(model.url).host !== CHUTES_HOST) return true;
  const hit = running.get(model.name);
  if (hit && Date.now() - hit.at < 120_000) return hit.up;
  try {
    let up = (await served(model.key)).has(model.name);
    if (!up) {
      const r = await fetch(`${API}/chutes/${encodeURIComponent(model.name)}`, { headers: { authorization: `Bearer ${model.key}` }, signal: AbortSignal.timeout(8_000) });
      up = r.ok ? !!((await r.json()) as { instances?: { active?: boolean }[] }).instances?.some((i) => i.active) : r.status === 404 ? false : hit?.up ?? true;
    }
    running.set(model.name, { at: Date.now(), up });
    return up;
  } catch {
    return hit?.up ?? true;
  }
}

/** Whether a model can read photos: Chutes lists it with image input, or its own setting says so. */
export async function readsImages(model: Model): Promise<boolean> {
  if (new URL(model.url).host !== CHUTES_HOST) return model.images === true;
  await served(model.key).catch(() => null);
  return sees.get(model.name) ?? false;
}

// A chip's speed changes by the minute. Each chip nobody has timed lately gets a one-word sealed
// question from the gateway itself, in the background, so real questions go to a quick chip from the start.
const probing = new Set<string>();
function probe(model: Model, chute: string, slots: Slot[]) {
  for (const inst of new Set(slots.map((sl) => sl.instance))) {
    const w = waits.get(inst);
    if (probing.has(inst) || (w && Date.now() - w.at < 120_000)) continue;
    const i = slots.findIndex((sl) => sl.instance === inst);
    const [sl] = slots.splice(i, 1);
    probing.add(inst);
    sealToChip(sl.key, { model: model.name, messages: [{ role: "user", content: "Reply with the word ok." }], max_tokens: 1, stream: true })
      .then(({ blob }) => invokeSealed(model, chute, sl.instance, sl.nonce, blob, 4))
      .then((r) => r.body?.cancel())
      .catch(() => {})
      .finally(() => probing.delete(inst));
  }
}

/** One instance key and one unused nonce. Chutes allows 10 lookups a minute per account, and each
 *  lookup gives 10 nonces per instance for 60 seconds, so the pool is shared by every visitor. */
export async function takeSlot(model: Model, chute: string): Promise<(Slot & { expiresAt: number }) | null> {
  const now = Date.now();
  let pool = pools.get(chute);
  if (!pool || now > pool.expiresAt - 5_000 || !pool.slots.length) {
    if (pool && now - pool.fetchedAt < 6_000 && pool.slots.length === 0) return null; // stay under the rate limit
    const r = await fetch(`${API}/e2e/instances/${chute}`, { headers: { authorization: `Bearer ${model.key}` }, signal: AbortSignal.timeout(10_000) });
    if (!r.ok) { pools.set(chute, { slots: [], expiresAt: now, fetchedAt: now }); return null; }
    const j = (await r.json()) as { instances: { instance_id: string; e2e_pubkey: string; nonces: string[] }[]; nonce_expires_in?: number };
    const slots = j.instances.flatMap((i) => i.nonces.map((nonce) => ({ instance: i.instance_id, key: i.e2e_pubkey, nonce })));
    pool = { slots, expiresAt: now + (j.nonce_expires_in ?? 55) * 1000, fetchedAt: now };
    pools.set(chute, pool);
  }
  if (!pool.slots.length) return null;
  probe(model, chute, pool.slots);
  const best = pool.slots.reduce((a: Slot, b: Slot) => (waitOf(b.instance) < waitOf(a.instance) ? b : a));
  if (waitOf(best.instance) > BUSY) return null;
  pool.slots.splice(pool.slots.indexOf(best), 1);
  return { ...best, expiresAt: pool.expiresAt };
}

// ---------- the chip's proof, fetched for the browser to check ----------
// Everything here is signed by someone other than us: the quote by Intel's hardware, the collateral by
// Intel, the GPU verdict by NVIDIA. The browser checks every signature (app/app/chip.ts), so passing
// these along lets the visitor's IP stay with us instead of reaching Chutes, Intel or NVIDIA.
const INTEL_PCS = "https://api.trustedservices.intel.com/tdx/certification/v4";
const NRAS = "https://nras.attestation.nvidia.com/v4/attest/gpu";

type Dcap = typeof import("../vendor/dcap-qvl/dcap-qvl-web.js");
const gd = globalThis as unknown as { __dcap?: Promise<Dcap>; __collateral?: Map<string, { at: number; c: unknown }> };
const dcap = () => (gd.__dcap ??= (async () => {
  const [mod, fs] = await Promise.all([import("../vendor/dcap-qvl/dcap-qvl-web.js"), import("node:fs")]);
  mod.initSync({ module: fs.readFileSync(`${process.cwd()}/lib/vendor/dcap-qvl/dcap-qvl-web_bg.wasm`) });
  return mod;
})());
const collaterals = (gd.__collateral ??= new Map());

/** Intel's signed collateral for a quote, kept for an hour per signing platform. */
export async function collateralFor(quote: Uint8Array) {
  const id = Buffer.from(await crypto.subtle.digest("SHA-256", quote.slice(632) as BufferSource)).toString("hex");
  const hit = collaterals.get(id);
  if (hit && Date.now() - hit.at < 3_600_000) return hit.c;
  const c = await (await dcap()).js_get_collateral(INTEL_PCS, quote);
  collaterals.set(id, { at: Date.now(), c });
  return c;
}

/** The chip's quote for the browser's nonce, Intel's collateral for it, and NVIDIA's verdict on its GPUs
 *  (whose evidence carries SHA256(nonce + key), the same value the quote carries). */
export async function proofFor(model: Model, instance: string, key: string, nonce: string) {
  const r = await fetch(`${API}/instances/${instance}/evidence?nonce=${nonce}`, { headers: { authorization: `Bearer ${model.key}` }, signal: AbortSignal.timeout(20_000) });
  if (!r.ok) throw new Error(`evidence ${r.status}`);
  const ev = (await r.json()) as { quote: string; gpu_evidence?: { certificate: string; evidence: string; arch: string }[] };
  const quote = Uint8Array.from(Buffer.from(ev.quote, "base64"));
  const gpus = ev.gpu_evidence ?? [];
  const bound = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nonce + key) as BufferSource)).toString("hex");
  const [collateral, nvidia] = await Promise.all([
    collateralFor(quote),
    gpus.length
      ? fetch(NRAS, { method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(30_000), body: JSON.stringify({ nonce: bound, arch: gpus[0].arch, evidence_list: gpus.map((g) => ({ certificate: g.certificate, evidence: g.evidence })) }) })
          .then(async (x) => (x.ok ? x.json() : null))
      : null,
  ]);
  return { quote: ev.quote, collateral, nvidia };
}

/** Passes one sealed request to its chip and returns the sealed event stream. Each `e2e` event is one
 *  sealed piece of the answer; the stream is cut after `maxEvents`, which caps the length of an answer
 *  the gateway cannot read. The cap holds only for a streamed answer, and the sealed request itself
 *  says whether to stream, so an answer that has not started streaming FIRST_PIECE after the question
 *  went out is cut too: a request sealed to come back in one piece sends nothing, not even headers,
 *  until it is finished, and would otherwise run unbounded. A streamed answer's first piece comes as
 *  soon as the chip starts; the gateway already steers questions away from chips that are slow to. */
const FIRST_PIECE = 12_000;
export async function invokeSealed(model: Model, chute: string, instance: string, nonce: string, blob: Uint8Array, maxEvents: number): Promise<Response> {
  const t0 = Date.now();
  const stop = new AbortController();
  const late = setTimeout(() => stop.abort(), FIRST_PIECE);
  let res: Response;
  try {
    res = await fetch(`${API}/e2e/invoke`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${model.key}`, "content-type": "application/octet-stream",
        "x-chute-id": chute, "x-instance-id": instance, "x-e2e-nonce": nonce, "x-e2e-stream": "true", "x-e2e-path": "/v1/chat/completions",
      },
      body: blob as unknown as BodyInit,
      signal: stop.signal,
    });
  } catch (e) {
    clearTimeout(late);
    noteWait(instance, 60_000); // never started within FIRST_PIECE: counts as a minute slow
    throw e;
  }
  // A chip that failed counts as a minute slow, so it gets new questions only when nothing quicker is left.
  noteWait(instance, res.ok ? Date.now() - t0 : 60_000);
  if (!res.ok || !res.body) { clearTimeout(late); return new Response(await res.text().catch(() => ""), { status: res.status }); }
  let events = 0, buf = "", streaming = false;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const cut = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, ctl) {
      buf += dec.decode(chunk, { stream: true });
      if (!streaming) {
        if (buf.trimStart().length < 6) return;
        if (!buf.trimStart().startsWith("data:")) { stop.abort(); ctl.error(new Error("not a stream")); return; }
        streaming = true; clearTimeout(late);
      }
      const lines = buf.split("\n");
      buf = lines.pop()!;
      for (const line of lines) {
        if (line.startsWith("data: ") && line.includes('"e2e"') && ++events > maxEvents) { ctl.enqueue(enc.encode("data: [DONE]\n\n")); ctl.terminate(); stop.abort(); return; }
        ctl.enqueue(enc.encode(line + "\n"));
      }
    },
    flush(ctl) { clearTimeout(late); if (buf) ctl.enqueue(enc.encode(buf)); },
  });
  return new Response(res.body.pipeThrough(cut), { status: 200, headers: { "content-type": "text/event-stream", "cache-control": "no-store" } });
}
