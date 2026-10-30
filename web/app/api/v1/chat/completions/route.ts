// OpenAI-compatible chat endpoint. The API key is a bundle of zero-knowledge request proofs.
// Nothing about the caller is read or kept: no IP, no headers beyond the key, no logs.
import { admit } from "@/lib/paranoid/gateway";
import { isRunning, readsImages } from "@/lib/paranoid/chips";
import { MAX_PHOTOS, PHOTO_QUESTIONS, photosIn } from "@/lib/paranoid/photos";
import { cleanBody, fitMessages, forwardChat } from "@/lib/paranoid/forward";
import { GATEWAY, pickModel } from "@/lib/paranoid/server";
import { searchContext, searchEnabled } from "@/lib/paranoid/search";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const oaiError = (status: number, code: string, message: string) =>
  Response.json({ error: { message, type: status === 401 ? "invalid_request_error" : "insufficient_quota", code } }, { status });

export async function POST(req: Request) {
  const key = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (!key) return oaiError(401, "missing_api_key", "Send your PARANOID key as the API key. Make one at /app.");
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return oaiError(400, "invalid_json", "The request body is not JSON."); }
  if (!Array.isArray(body.messages)) return oaiError(400, "invalid_request", "`messages` must be a list.");

  const model = pickModel(body.model);
  if (!(await isRunning(model))) return oaiError(503, "model_unavailable", "This model is not running right now. Pick another one; no question was spent.");
  // Photos cost more to read, so each one adds PHOTO_QUESTIONS (lib/paranoid/photos.ts).
  const photos = photosIn(body.messages);
  if (photos > MAX_PHOTOS) return oaiError(400, "too_many_photos", `Send at most ${MAX_PHOTOS} photos with one message; no question was spent.`);
  if (photos && !(await readsImages(model))) return oaiError(400, "no_photos", "This model cannot see photos. Pick one that can; no question was spent.");
  // A model with a price per message takes a conversation of bounded length: the oldest turns go first.
  if (model.maxInput) {
    const fitted = fitMessages(body.messages as { role?: unknown; content?: unknown }[], model.maxInput);
    if (!fitted) return oaiError(400, "message_too_long", `${model.label} takes messages of up to ${model.maxInput.toLocaleString("en-US")} characters. Shorten it; no question was spent.`);
    body.messages = fitted;
  }
  // The tickets are held while the model is asked and spent once it starts answering, so a model that is down
  // costs nothing.
  let v;
  try { v = await admit(GATEWAY, key, model.cost + photos * PHOTO_QUESTIONS, true); }
  catch { return oaiError(503, "not_open", "The gateway could not read the member list on Solana just now. Try again in a moment."); }
  if (!v.ok) return oaiError(v.status, v.code, v.message);
  const held = v.hold;
  const unanswered = () => { held?.release(); return oaiError(502, "model_unreachable", "The model did not answer, so no question was spent. Try again."); };

  // `web: true` asks the gateway to search first. The engines see the gateway, never the caller;
  // a search that fails leaves the question to the model alone rather than eating the ticket.
  if (body.web === true && searchEnabled()) {
    const msgs = body.messages as { role?: unknown; content?: unknown }[];
    const last = [...msgs].reverse().find((m) => m.role === "user" && typeof m.content === "string");
    if (last) {
      const ctx = await searchContext(String(last.content).slice(0, 400)).catch(() => null);
      if (ctx) body.messages = [{ role: "system", content: ctx }, ...msgs];
    }
  }

  try {
    const res = await forwardChat(model.url, model.key, cleanBody(body, model.name, model.maxTokens, model.body));
    // The model refused or failed: pass its own error on, and give the tickets back.
    if (!res.ok) { held?.release(); return res; }
    held?.commit();
    res.headers.set("x-paranoid-requests-left", String(v.slotsLeft));
    return res;
  } catch {
    return unanswered();
  }
}
