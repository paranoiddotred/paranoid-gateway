// Hands a browser what it needs to seal one question to a model's chip: the TEE instance's public
// key and one single-use invoke nonce. The browser checks that key against the chip's own attestation
// before it uses it, so this route cannot swap in a key of ours. Model: the x-paranoid-model header.
import { chuteOf, takeSlot } from "@/lib/paranoid/chips";
import { isAci } from "@/lib/paranoid/aci";
import { MAX_OUTPUT_TOKENS } from "@/lib/paranoid/forward";
import { pickModel } from "@/lib/paranoid/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const none = (message: string) => Response.json({ error: { code: "no_chip", message } }, { status: 404 });

export async function GET(req: Request) {
  const model = pickModel(req.headers.get("x-paranoid-model"));
  // An ACI gateway needs no slot: the browser checks the gateway's proof and seals to a key it names.
  if (isAci(model)) return Response.json({ kind: "aci", model: model.name, chute: "", instance: "", key: "", nonce: "", expiresAt: 0, maxTokens: model.maxTokens ?? MAX_OUTPUT_TOKENS, body: model.body ?? {} }, { headers: { "cache-control": "no-store" } });
  const chute = await chuteOf(model).catch(() => null);
  if (!chute) return none("This model does not run on a chip that takes sealed questions.");
  const slot = await takeSlot(model, chute).catch(() => null);
  if (!slot) return Response.json({ error: { code: "chip_busy", message: "This model's chips are too busy for sealed questions right now." } }, { status: 503 });
  return Response.json(
    { model: model.name, chute, ...slot, maxTokens: model.maxTokens ?? MAX_OUTPUT_TOKENS, body: model.body ?? {} },
    { headers: { "cache-control": "no-store" } },
  );
}
