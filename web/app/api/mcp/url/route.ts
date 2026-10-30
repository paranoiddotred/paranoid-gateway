// Turns a connector code into a paranoid.red/mcp URL. The code arrives in the body, never in a URL, and is
// sealed (lib/paranoid/remote.ts) before it goes anywhere a log could see it. Nothing is stored.
import { mcpReady, parseCode, seal, today } from "@/lib/paranoid/remote";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  if (!mcpReady()) return Response.json({ error: "MCP URLs are not switched on here." }, { status: 503 });
  const { code } = (await req.json().catch(() => ({}))) as { code?: unknown };
  const secret = typeof code === "string" ? parseCode(code) : null;
  if (secret === null) return Response.json({ error: "That is not a connector code. Copy it from the Keys tab at paranoid.red/app: it looks like <digits>.<digits>." }, { status: 400 });
  const t = await today(secret).catch(() => "The member list on Solana could not be read just now. Try again in a moment.");
  if (typeof t === "string") return Response.json({ error: t }, { status: 404 });
  return Response.json({ path: `/mcp/${seal(secret)}` });
}
