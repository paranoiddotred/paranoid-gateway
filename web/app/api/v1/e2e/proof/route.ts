// The proof behind one chip, for the browser to check before it seals a question to it: the TDX quote
// for the browser's own nonce, Intel's collateral, and NVIDIA's verdict on the GPUs. All of it is
// signed by Intel or NVIDIA, so this route can pass it along but cannot change it unnoticed.
// Headers: x-paranoid-model, x-e2e-instance, x-e2e-key (the instance key, base64), x-e2e-attest (64 hex).
import { chuteOf, proofFor } from "@/lib/paranoid/chips";
import { pickModel } from "@/lib/paranoid/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const model = pickModel(req.headers.get("x-paranoid-model"));
  const instance = req.headers.get("x-e2e-instance") ?? "", key = req.headers.get("x-e2e-key") ?? "", nonce = req.headers.get("x-e2e-attest") ?? "";
  if (!/^[0-9a-f]{64}$/.test(nonce) || !/^[0-9a-f-]{36}$/.test(instance) || key.length < 1500) return Response.json({ error: { code: "bad_request", message: "Missing chip, key or nonce." } }, { status: 400 });
  if (!(await chuteOf(model).catch(() => null))) return Response.json({ error: { code: "no_chip", message: "This model does not run on a chip." } }, { status: 404 });
  try {
    return Response.json(await proofFor(model, instance, key, nonce), { headers: { "cache-control": "no-store" } });
  } catch {
    return Response.json({ error: { code: "proof_unreachable", message: "The chip's proof could not be fetched just now." } }, { status: 502 });
  }
}
