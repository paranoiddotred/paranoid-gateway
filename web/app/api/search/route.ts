// Web search for a question sealed to a chip. The chip picked the search words; this route only ever
// sees those words, never the question, and runs them only with the receipt from the paid sealed call
// that produced them. Search engines and websites see the gateway's address, never the person's.
import { takeReceipt } from "@/lib/paranoid/receipts";
import { searchContext, searchEnabled } from "@/lib/paranoid/search";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let body: { q?: unknown; receipt?: unknown; deep?: unknown };
  try { body = await req.json(); } catch { return Response.json({ error: "The body is not JSON." }, { status: 400 }); }
  if (typeof body.receipt !== "string" || !takeReceipt(body.receipt)) return Response.json({ error: "This search has no receipt from a paid question." }, { status: 402 });
  const q = typeof body.q === "string" ? body.q.trim().slice(0, 160) : "";
  if (!q || !searchEnabled()) return Response.json({ context: null });
  return Response.json({ context: await searchContext(q, body.deep === true).catch(() => null) });
}
