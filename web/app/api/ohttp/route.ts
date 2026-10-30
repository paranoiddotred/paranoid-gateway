// The unseal side of the IP shield. The relay posts an opaque blob here; this route opens it, runs
// the inner request against our own API (an allowlist, never an open proxy), and seals the answer
// back for the same caller. The caller's address never appears: only the relay's does.
import { openRequest, serverKeys } from "@/lib/paranoid/ohttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ALLOWED_PATHS = new Set(["/api/v1/chat/completions", "/api/v1/models", "/api/v1/used", "/api/v1/e2e", "/api/v1/e2e/key", "/api/v1/e2e/proof", "/api/search", "/api/sync", "/api/v1/e2e/aci"]);
const KEEP_REQUEST_HEADERS = new Set(["authorization", "content-type", "accept", "x-paranoid-model", "x-e2e-instance", "x-e2e-nonce", "x-e2e-key", "x-e2e-attest", "x-paranoid-search", "x-e2ee-version", "x-client-pub-key", "x-model-pub-key", "x-e2ee-nonce", "x-e2ee-timestamp"]);
const KEEP_RESPONSE_HEADERS = new Set(["content-type", "x-paranoid-requests-left", "x-paranoid-search-receipt", "x-e2ee-applied"]);

const g = globalThis as unknown as { __ohttpKeys?: Promise<Awaited<ReturnType<typeof serverKeys>>> };

export async function POST(req: Request) {
  const seed = process.env.PARANOID_OHTTP_SEED;
  if (!seed) return new Response("no key configured", { status: 503 });
  // A chunked request (draft-ietf-ohai-chunked-ohttp) gets its answer sealed piece by piece as it streams in.
  const type = req.headers.get("content-type") ?? "";
  const chunked = type === "message/ohttp-chunked-req";
  if (!chunked && type !== "message/ohttp-req") return new Response("expected message/ohttp-req", { status: 415 });
  const wire = new Uint8Array(await req.arrayBuffer());
  if (wire.length < 40 || wire.length > 1_000_000) return new Response("bad size", { status: 400 });

  let opened;
  try {
    const { keyPair } = await (g.__ohttpKeys ??= serverKeys(seed));
    opened = await openRequest(keyPair, wire, chunked);
  } catch {
    return new Response("cannot open", { status: 400 });
  }
  const { inner, seal, sealChunked } = opened;
  if (!ALLOWED_PATHS.has(inner.path) || (inner.method !== "POST" && inner.method !== "GET")) {
    return new Response("path not allowed", { status: 403 });
  }

  const origin = process.env.PARANOID_SELF_URL ?? new URL(req.url).origin;
  const headers: Record<string, string> = {};
  for (const [n, v] of inner.headers) if (KEEP_REQUEST_HEADERS.has(n)) headers[n] = v;
  const res = await fetch(origin + inner.path, {
    method: inner.method,
    headers,
    body: inner.method === "POST" ? (inner.body as unknown as BodyInit) : undefined,
    cache: "no-store",
  });
  const kept: [string, string][] = [];
  res.headers.forEach((v, n) => { if (KEEP_RESPONSE_HEADERS.has(n.toLowerCase())) kept.push([n.toLowerCase(), v]); });
  if (chunked) {
    const out = await sealChunked(res.status, kept, res.body);
    return new Response(out, { headers: { "content-type": "message/ohttp-chunked-res", "cache-control": "no-store" } });
  }
  const body = new Uint8Array(await res.arrayBuffer());
  const out = await seal({ status: res.status, headers: kept, body });
  return new Response(out as unknown as BodyInit, { headers: { "content-type": "message/ohttp-res", "cache-control": "no-store" } });
}
