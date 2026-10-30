// paranoid.red/mcp/<URL key>: PARANOID as a remote MCP server for clients that connect to a URL, such as Claude's
// custom connectors. Streamable HTTP with JSON replies only (no event stream, no sessions). What this server can
// see, and how it keeps parallel calls and other devices off each other's tickets: lib/paranoid/remote.ts.
import { ask, balance, mcpReady, models, unseal } from "@/lib/paranoid/remote";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 120;

const VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const TOOLS = [
  {
    name: "ask",
    description: "Ask one of PARANOID's AI models a question. It goes with a zero-knowledge proof that it was paid for, made on PARANOID's server for this URL. Spends the model's price in questions (see the models tool).",
    inputSchema: {
      type: "object",
      properties: {
        question: { type: "string", description: "The question, as you would type it into a chat." },
        model: { type: "string", description: "A model id from the models tool. Leave it out for the default model." },
        system: { type: "string", description: "Instructions for the model, if you want any." },
      },
      required: ["question"],
    },
  },
  { name: "models", description: "List PARANOID's models and how many questions one message to each costs.", inputSchema: { type: "object", properties: {} } },
  { name: "balance", description: "How many questions this membership has left, how many this URL can spend, and the last day they can be used.", inputSchema: { type: "object", properties: {} } },
];

type Msg = { jsonrpc?: string; id?: string | number | null; method?: string; params?: Record<string, unknown> };
const reply = (id: Msg["id"], result: unknown) => ({ jsonrpc: "2.0", id, result });
const failure = (id: Msg["id"], code: number, message: string) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

async function handle(secret: bigint, m: Msg) {
  if (m.id === undefined) return null; // a notification: nothing to answer
  const p = m.params ?? {};
  switch (m.method) {
    case "initialize": {
      const asked = String(p.protocolVersion ?? "");
      return reply(m.id, {
        protocolVersion: VERSIONS.includes(asked) ? asked : VERSIONS[0],
        capabilities: { tools: {} },
        serverInfo: { name: "paranoid", title: "PARANOID", version: "1.3.0" },
      });
    }
    case "ping":
      return reply(m.id, {});
    case "tools/list":
      return reply(m.id, { tools: TOOLS });
    case "tools/call": {
      const a = (p.arguments ?? {}) as Record<string, unknown>;
      let out: { text: string; error?: true };
      if (p.name === "ask") {
        if (typeof a.question !== "string" || !a.question.trim()) return failure(m.id, -32602, "ask needs a question.");
        if (a.question.length > 20_000) return failure(m.id, -32602, "The question is longer than 20,000 characters.");
        out = await ask(secret, a.question, typeof a.model === "string" ? a.model : undefined, typeof a.system === "string" ? a.system : undefined);
      } else if (p.name === "models") out = await models();
      else if (p.name === "balance") out = await balance(secret);
      else return failure(m.id, -32602, `There is no tool called ${String(p.name)}.`);
      return reply(m.id, { content: [{ type: "text", text: out.text }], isError: out.error ?? false });
    }
    default:
      return failure(m.id, -32601, `${String(m.method)} is not supported.`);
  }
}

export async function POST(req: Request, ctx: { params: Promise<{ token: string }> }) {
  if (!mcpReady()) return Response.json(failure(null, -32000, "MCP URLs are not switched on here."), { status: 503 });
  const secret = unseal((await ctx.params).token);
  if (secret === null) return Response.json(failure(null, -32001, "This PARANOID MCP URL is not valid. Make a new one at paranoid.red/mcp."), { status: 404 });
  let body: unknown;
  try { body = await req.json(); } catch { return Response.json(failure(null, -32700, "The body is not JSON."), { status: 400 }); }
  const batch = Array.isArray(body);
  const msgs = (batch ? body : [body]) as Msg[];
  const out = (await Promise.all(msgs.map((m) => handle(secret, m).catch(() => failure(m.id, -32603, "Something went wrong on our side. No question was spent."))))).filter((r) => r !== null);
  if (out.length === 0) return new Response(null, { status: 202 });
  return Response.json(batch ? out : out[0]);
}

const postOnly = () => new Response("This MCP endpoint answers POST requests.", { status: 405, headers: { allow: "POST" } });
export const GET = postOnly;
export const DELETE = postOnly;
