// The gateway's public sealing key (application/ohttp-keys). It is derived from one fixed seed, so
// every visitor gets the same bytes and anyone can compare them.
import { serverKeys } from "@/lib/paranoid/ohttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const seed = process.env.PARANOID_OHTTP_SEED;
  if (!seed) return new Response("no key configured", { status: 503 });
  const { config } = await serverKeys(seed);
  return new Response(config as unknown as BodyInit, {
    headers: { "content-type": "application/ohttp-keys", "cache-control": "public, max-age=3600" },
  });
}
