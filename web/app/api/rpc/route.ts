// Read-and-send relay to the Solana RPC, so the browser never needs the provider's key.
import { RPC } from "@/lib/paranoid/server";

export const dynamic = "force-dynamic";

const ALLOWED = new Set(["getAccountInfo", "getMultipleAccounts", "getProgramAccounts", "getBalance", "getTokenAccountBalance", "getLatestBlockhash", "getSlot", "getBlockTime", "getSignatureStatuses", "sendTransaction", "simulateTransaction", "getMinimumBalanceForRentExemption", "getEpochInfo", "getHealth", "getFeeForMessage", "getTokenAccountsByOwner", "getBlockHeight", "isBlockhashValid"]);

// Every open /app polls the same member list and config. Identical reads within a few seconds share one
// upstream call, so the RPC load stays flat however many people watch (launch readiness rule 2).
const SHARED = new Set(["getAccountInfo", "getMultipleAccounts", "getProgramAccounts", "getSlot", "getBlockTime", "getEpochInfo", "getMinimumBalanceForRentExemption"]);
const TTL_MS = 3000;
type Call = { jsonrpc?: string; id?: unknown; method: string; params?: unknown };
const shared = new Map<string, { at: number; reply: Promise<{ status: number; json: { result?: unknown; error?: unknown } }> }>();

async function upstream(body: unknown) {
  const res = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, json: await res.json() };
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  const calls: Call[] = Array.isArray(body) ? body : [body];
  if (!body || calls.some((c) => !c || !ALLOWED.has(c.method))) return Response.json({ error: "method not allowed" }, { status: 400 });

  const one = Array.isArray(body) ? null : (body as Call);
  if (!one || !SHARED.has(one.method)) {
    const res = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    return new Response(res.body, { status: res.status, headers: { "content-type": "application/json" } });
  }

  const key = one.method + JSON.stringify(one.params ?? []);
  const now = Date.now();
  let hit = shared.get(key);
  if (!hit || now - hit.at > TTL_MS) {
    hit = { at: now, reply: upstream({ jsonrpc: "2.0", id: 1, method: one.method, params: one.params }) };
    shared.set(key, hit);
    hit.reply.then((r) => { if (r.status !== 200 || r.json.error) shared.delete(key); }, () => shared.delete(key));
    if (shared.size > 500) for (const [k, v] of shared) if (now - v.at > TTL_MS) shared.delete(k);
  }
  try {
    const { status, json } = await hit.reply;
    return Response.json({ ...json, jsonrpc: "2.0", id: one.id ?? null }, { status });
  } catch {
    return Response.json({ jsonrpc: "2.0", id: one.id ?? null, error: { code: -32000, message: "RPC unreachable" } }, { status: 502 });
  }
}
