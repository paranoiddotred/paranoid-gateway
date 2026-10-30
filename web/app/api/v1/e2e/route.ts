// A question sealed to the model's chip (lib/paranoid/sealchip.ts). The gateway checks the PARANOID
// key like any request, then passes the sealed bytes to Chutes without being able to open them, and
// streams the sealed answer back. Headers: authorization (the key), x-paranoid-model, x-e2e-instance,
// x-e2e-nonce, and x-paranoid-search (how many searches, 1 to 4) when the chip is asked for search words;
// the body is the sealed blob.
import { admit } from "@/lib/paranoid/gateway";
import { chuteOf, invokeSealed, isRunning } from "@/lib/paranoid/chips";
import { MAX_OUTPUT_TOKENS } from "@/lib/paranoid/forward";
import { issueReceipt } from "@/lib/paranoid/receipts";
import { GATEWAY, pickModel } from "@/lib/paranoid/server";
import { sealedPhotoFloor } from "@/lib/paranoid/photos";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const oaiError = (status: number, code: string, message: string) =>
  Response.json({ error: { message, type: status === 401 ? "invalid_request_error" : "insufficient_quota", code } }, { status });

export async function POST(req: Request) {
  const key = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (!key) return oaiError(401, "missing_api_key", "Send your PARANOID key as the API key. Make one at /app.");
  const instance = req.headers.get("x-e2e-instance") ?? "", nonce = req.headers.get("x-e2e-nonce") ?? "";
  const model = pickModel(req.headers.get("x-paranoid-model"));
  const chute = await chuteOf(model).catch(() => null);
  if (!chute || !instance || !nonce) return oaiError(400, "no_chip", "This question was not sealed to a chip of this model.");
  const blob = new Uint8Array(await req.arrayBuffer());
  if (blob.length < 1200 || blob.length > 1_000_000) return oaiError(400, "bad_size", "The sealed question has the wrong size.");

  if (!(await isRunning(model))) return oaiError(503, "model_unavailable", "This model is not running right now. Pick another one; no question was spent.");
  // The ticket is only held while the chip is asked: it is spent once the chip starts answering, and
  // given back if the chip never does, so the browser can send the same question the usual way.
  let v;
  // The gateway cannot see photos in a sealed question, so a large one pays as if it held them.
  try { v = await admit(GATEWAY, key, model.cost + sealedPhotoFloor(blob.length), true); }
  catch { return oaiError(503, "not_open", "The gateway could not read the member list on Solana just now. Try again in a moment."); }
  if (!v.ok) return oaiError(v.status, v.code, v.message);
  const held = v.hold;
  const busy = () => { held?.release(); return oaiError(503, "chip_busy", "The chip was too busy to start answering, so nothing was spent."); };

  try {
    // Thinking arrives as sealed pieces too, so the cap leaves room for it on top of the answer.
    const cap = (model.maxTokens ?? MAX_OUTPUT_TOKENS) * 2 + 64;
    const res = await invokeSealed(model, chute, instance, nonce, blob, cap);
    if (!res.ok) return busy();
    held?.commit();
    res.headers.set("x-paranoid-requests-left", String(v.slotsLeft));
    // A call that asked the chip for search words may run that many web searches with them (app/api/search).
    const searches = Math.min(4, Math.max(0, Math.floor(Number(req.headers.get("x-paranoid-search")) || 0)));
    if (searches) res.headers.set("x-paranoid-search-receipt", Array.from({ length: searches }, issueReceipt).join(","));
    return res;
  } catch {
    return busy();
  }
}
