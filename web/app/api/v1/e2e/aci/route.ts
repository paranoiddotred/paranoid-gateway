// A question sealed in the browser to an ACI gateway (lib/paranoid/aci.ts, app/app/aci.ts).
// GET: the gateway's attestation report for the browser's nonce and Intel's collateral for it.
//   Headers: x-paranoid-model, x-e2e-attest (64 hex). Signed by Intel's hardware, so passing it along
//   cannot change it unnoticed.
// POST: the PARANOID key is checked like any request, then the request, whose message contents the
//   browser encrypted with E2EE v2, goes on with our account key. Headers: authorization, x-paranoid-model,
//   the five x-e2ee-* headers, and x-paranoid-search (1 to 4) when the model is asked for search words.
import { admit } from "@/lib/paranoid/gateway";
import { aciReport, E2EE_HEADERS, forwardAci, isAci } from "@/lib/paranoid/aci";
import { cleanBody } from "@/lib/paranoid/forward";
import { issueReceipt } from "@/lib/paranoid/receipts";
import { GATEWAY, pickModel } from "@/lib/paranoid/server";
import { sealedPhotoFloor } from "@/lib/paranoid/photos";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const oaiError = (status: number, code: string, message: string) =>
  Response.json({ error: { message, type: status === 401 ? "invalid_request_error" : "insufficient_quota", code } }, { status });
// Every message content on the way out must be E2EE v2 ciphertext: lowercase hex of a 32-byte X25519 key,
// a 12-byte nonce and the sealed text with its 16-byte tag, so at least 122 hex characters.
const SEALED = /^[0-9a-f]{122,}$/;

export async function GET(req: Request) {
  const model = pickModel(req.headers.get("x-paranoid-model"));
  const nonce = req.headers.get("x-e2e-attest") ?? "";
  if (!isAci(model)) return oaiError(404, "no_chip", "This model does not take questions sealed in the browser.");
  if (!/^[0-9a-f]{64}$/.test(nonce)) return oaiError(400, "bad_request", "Missing nonce.");
  try {
    return Response.json(await aciReport(model, nonce), { headers: { "cache-control": "no-store" } });
  } catch {
    return oaiError(502, "proof_unreachable", "The gateway's proof could not be fetched just now.");
  }
}

export async function POST(req: Request) {
  const key = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (!key) return oaiError(401, "missing_api_key", "Send your PARANOID key as the API key. Make one at /app.");
  const model = pickModel(req.headers.get("x-paranoid-model"));
  if (!isAci(model)) return oaiError(400, "no_chip", "This question was not sealed to this model.");
  const e2ee: Record<string, string> = {};
  for (const h of E2EE_HEADERS) { const v = req.headers.get(h); if (!v || v.length > 200) return oaiError(400, "no_seal", "The question is missing its seal."); e2ee[h] = v; }
  const raw = await req.text();
  if (raw.length > 1_000_000) return oaiError(400, "bad_size", "The sealed question is too large.");
  let body: Record<string, unknown>;
  try { body = JSON.parse(raw); } catch { return oaiError(400, "invalid_json", "The request body is not JSON."); }
  const messages = body.messages;
  // Only sealed text passes: a plain message here would reach the model gateway readable by us.
  if (!Array.isArray(messages) || !messages.length || !messages.every((m) => typeof m?.content === "string" && SEALED.test(m.content)))
    return oaiError(400, "not_sealed", "Every message must be sealed in the browser.");

  // The ticket is held while the gateway is asked and spent once it starts answering.
  let v;
  try { v = await admit(GATEWAY, key, model.cost + sealedPhotoFloor(raw.length / 2), true); }
  catch { return oaiError(503, "not_open", "The gateway could not read the member list on Solana just now. Try again in a moment."); }
  if (!v.ok) return oaiError(v.status, v.code, v.message);
  const held = v.hold;
  const busy = () => { held?.release(); return oaiError(503, "chip_busy", "The model's gateway did not start answering, so nothing was spent."); };

  try {
    // The length cap and the other settings stay in clear text, so the gateway enforces them as for any model.
    const res = await forwardAci(model, { ...cleanBody(body, model.name, model.maxTokens, model.body), stream: true }, e2ee);
    if (!res.ok) return busy();
    held?.commit();
    res.headers.set("x-paranoid-requests-left", String(v.slotsLeft));
    const searches = Math.min(4, Math.max(0, Math.floor(Number(req.headers.get("x-paranoid-search")) || 0)));
    if (searches) res.headers.set("x-paranoid-search-receipt", Array.from({ length: searches }, issueReceipt).join(","));
    return res;
  } catch {
    return busy();
  }
}
