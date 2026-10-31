// paranoid.red/mcp/<URL key>/chat: the same membership as the MCP URL, for a chat window that wants the answer as
// it is written (the PARANOID browser extension). Takes a whole conversation and returns the model's own
// server-sent events. Tickets, proofs and what this server can see are exactly as for the MCP `ask` tool
// (lib/paranoid/remote.ts).
import { mcpReady, streamChat, unseal } from "@/lib/paranoid/remote";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

const MAX_MESSAGES = 40;
const MAX_CHARS = 60_000;
const ROLES = new Set(["system", "user", "assistant"]);
const refuse = (status: number, message: string) => Response.json({ error: { message } }, { status });

export async function POST(req: Request, ctx: { params: Promise<{ token: string }> }) {
  if (!mcpReady()) return refuse(503, "MCP URLs are not switched on here.");
  const secret = unseal((await ctx.params).token);
  if (secret === null) return refuse(404, "This PARANOID URL is not valid. Make a new one at paranoid.red/mcp.");
  let body: { model?: unknown; messages?: unknown };
  try { body = await req.json(); } catch { return refuse(400, "The body is not JSON."); }
  const messages = body.messages;
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > MAX_MESSAGES
    || !messages.every((m) => m && ROLES.has(m.role) && typeof m.content === "string")) {
    return refuse(400, `Send \`messages\`: 1 to ${MAX_MESSAGES} turns, each a role (system, user or assistant) and text.`);
  }
  if (messages.reduce((n: number, m: { content: string }) => n + m.content.length, 0) > MAX_CHARS) {
    return refuse(400, `The conversation is longer than ${MAX_CHARS.toLocaleString("en-US")} characters. Start a new chat.`);
  }
  try {
    return await streamChat(secret, messages.map((m: { role: string; content: string }) => ({ role: m.role, content: m.content })), typeof body.model === "string" ? body.model : undefined);
  } catch {
    return refuse(500, "Something went wrong on our side. No question was spent.");
  }
}
