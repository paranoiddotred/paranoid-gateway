import { CHUTES_HOST, chuteOf, isRunning, readsImages } from "@/lib/paranoid/chips";
import { MODELS } from "@/lib/paranoid/server";
import { isAci } from "@/lib/paranoid/aci";

export const dynamic = "force-dynamic";

export async function GET() {
  // The first model is the default. `label`, `cost` (questions per message), `available` (Chutes has it
  // running right now) and `sealed` (it runs on a TEE chip or behind an attested gateway, so questions can be sealed to it) are ours;
  // OpenAI clients ignore them. `images` says the model reads photos; each photo adds PHOTO_QUESTIONS.
  // `sleeps`: a Chutes model nobody asked for a while needs a minute or two to wake; the others are always up.
  const [up, chips, eyes] = await Promise.all([
    Promise.all(MODELS.map((m) => isRunning(m))),
    Promise.all(MODELS.map((m) => chuteOf(m).catch(() => null))),
    Promise.all(MODELS.map((m) => readsImages(m).catch(() => false))),
  ]);
  return Response.json({ object: "list", data: MODELS.map((m, i) => ({ id: m.name, object: "model", created: 0, owned_by: "paranoid", label: m.label, cost: m.cost, available: up[i], sealed: chips[i] !== null || isAci(m), images: eyes[i], sleeps: new URL(m.url).host === CHUTES_HOST })) });
}
