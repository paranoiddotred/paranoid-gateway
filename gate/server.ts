// The PARANOID gateway on its own: every route that sees a question, a ticket or a key, served by plain
// Node from the same route files the site uses (web/app/...), so the code in the box is the code people
// can read. It also serves the public pieces a connector needs from one address (chain reads, circuit files).
// Pages, docs, sealed sync boxes and the shop stay on the site.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { chipInfo, chipKey, chipQuote, inTee, statementOf } from "./tee.ts";

const PORT = Number(process.env.PORT ?? 8080);
const SITE = (process.env.PARANOID_SITE_URL ?? "https://paranoid.red").replace(/\/$/, "");
const ORIGINS = new Set((process.env.PARANOID_CORS_ORIGINS ?? "https://paranoid.red,https://www.paranoid.red").split(",").map((s) => s.trim()).filter(Boolean));

// The route code reads its files (circuit, chip verifier) relative to the site folder.
process.chdir(fileURLToPath(new URL("../web/", import.meta.url)));
// Requests that arrive sealed (the IP shield) are opened here and run against this same server, never
// against an outside address: an opened request must not leave the box. Set, not defaulted, so a copied
// site setting cannot send it out.
process.env.PARANOID_SELF_URL = `http://127.0.0.1:${PORT}`;
// On the chip, the key that opens sealed requests is derived inside it, never handed in from outside:
// nobody holding the server's settings, the operator included, can open what the IP shield sealed.
if (inTee()) process.env.PARANOID_OHTTP_SEED = await chipKey("paranoid/ohttp/v1");

type Handler = (req: Request, ctx: { params: Promise<Record<string, string>> }) => Response | Promise<Response>;
type Module = Partial<Record<"GET" | "POST" | "DELETE", Handler>>;

const ROUTES: [RegExp, string][] = [
  [/^\/api\/v1\/chat\/completions$/, "app/api/v1/chat/completions/route.ts"],
  [/^\/api\/v1\/models$/, "app/api/v1/models/route.ts"],
  [/^\/api\/v1\/used$/, "app/api/v1/used/route.ts"],
  [/^\/api\/v1\/e2e$/, "app/api/v1/e2e/route.ts"],
  [/^\/api\/v1\/e2e\/key$/, "app/api/v1/e2e/key/route.ts"],
  [/^\/api\/v1\/e2e\/proof$/, "app/api/v1/e2e/proof/route.ts"],
  [/^\/api\/v1\/e2e\/aci$/, "app/api/v1/e2e/aci/route.ts"],
  [/^\/api\/ohttp$/, "app/api/ohttp/route.ts"],
  [/^\/api\/ohttp\/config$/, "app/api/ohttp/config/route.ts"],
  [/^\/api\/search$/, "app/api/search/route.ts"],
  [/^\/api\/mcp\/url$/, "app/api/mcp/url/route.ts"],
  [/^\/mcp\/(?<token>[^/]+)$/, "app/mcp/[token]/route.ts"],
  [/^\/api\/x402\/join$/, "app/api/x402/join/route.ts"],
  [/^\/api\/zec$/, "app/api/zec/route.ts"],
  [/^\/api\/zec\/status$/, "app/api/zec/status/route.ts"],
  [/^\/api\/rpc$/, "app/api/rpc/route.ts"],
];

/** The circuit files and prover the browser and the connector download, the same bytes the site serves. */
const ZK: Record<string, string> = { "snarkjs.min.js": "text/javascript", "request.wasm": "application/wasm", "request.zkey": "application/octet-stream" };

/** The chip's proof for a caller's nonce: a TDX quote naming this gateway's OHTTP key, the boot log and
 *  compose file to check what runs, and Intel's signed collateral to check the quote with. */
async function attest(url: URL): Promise<Response> {
  if (!inTee()) return new Response("This gateway is not running on a confidential chip.", { status: 404 });
  const nonce = url.searchParams.get("nonce") ?? "";
  if (!/^[0-9a-f]{64}$/.test(nonce)) return new Response("nonce must be 32 bytes of lowercase hex", { status: 400 });
  const { serverKeys } = await import(new URL("../web/lib/paranoid/ohttp.ts", import.meta.url).href);
  const { collateralFor } = await import(new URL("../web/lib/paranoid/chips.ts", import.meta.url).href);
  const keyConfig = Buffer.from((await serverKeys(process.env.PARANOID_OHTTP_SEED!)).config).toString("base64");
  const [{ appId, compose }, q] = await Promise.all([chipInfo(), chipQuote(statementOf(keyConfig, nonce))]);
  // Intel's collateral can be briefly unreachable; the browser then refuses, it never skips the check.
  const collateral = await collateralFor(Uint8Array.from(Buffer.from(q.quote, "hex"))).catch(() => null);
  return Response.json({ key_config: keyConfig, nonce, report_data: q.reportData, quote: q.quote, event_log: q.eventLog, app_compose: compose, app_id: appId, collateral },
    { headers: { "cache-control": "no-store" } });
}

const modules = new Map<string, Promise<Module>>();
const load = (file: string) => {
  if (!modules.has(file)) modules.set(file, import(new URL(`../web/${file}`, import.meta.url).href) as Promise<Module>);
  return modules.get(file)!;
};

/** Sealed sync boxes live on the site; a sealed request for one is passed on unopened past this box. */
async function toSite(req: Request, path: string): Promise<Response> {
  const headers = new Headers();
  for (const n of ["authorization", "content-type", "accept"]) { const v = req.headers.get(n); if (v) headers.set(n, v); }
  const r = await fetch(SITE + path, { method: req.method, headers, body: req.method === "GET" ? undefined : await req.arrayBuffer() });
  return new Response(r.body, { status: r.status, headers: { "content-type": r.headers.get("content-type") ?? "application/octet-stream" } });
}

async function route(req: Request): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === "/" || url.pathname === "/health") return Response.json({ status: "ok", service: "paranoid-gateway" });
  if (url.pathname === "/api/sync") return toSite(req, url.pathname + url.search);
  if (url.pathname === "/api/gate/attest" && req.method === "GET") return attest(url);
  const zk = /^\/zk\/([a-z.]+)$/.exec(url.pathname)?.[1];
  if (zk && ZK[zk] && req.method === "GET") {
    return new Response(await readFile(`public/zk/${zk}`), { headers: { "content-type": ZK[zk], "cache-control": "public, max-age=3600" } });
  }
  for (const [pattern, file] of ROUTES) {
    const m = pattern.exec(url.pathname);
    if (!m) continue;
    const handler = (await load(file))[req.method as "GET" | "POST" | "DELETE"];
    if (!handler) return new Response("method not allowed", { status: 405 });
    return handler(req, { params: Promise.resolve({ ...m.groups }) });
  }
  return new Response("not found", { status: 404 });
}

function cors(origin: string | undefined, res: ServerResponse, requested?: string) {
  if (!origin || !ORIGINS.has(origin)) return;
  res.setHeader("access-control-allow-origin", origin);
  res.setHeader("vary", "origin");
  res.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
  if (requested) res.setHeader("access-control-allow-headers", requested);
  res.setHeader("access-control-expose-headers", "x-paranoid-requests-left, x-paranoid-search-receipt, x-e2ee-applied, payment-required, payment-response");
  res.setHeader("access-control-max-age", "600");
}

async function serve(nreq: IncomingMessage, nres: ServerResponse) {
  const origin = nreq.headers.origin;
  if (nreq.method === "OPTIONS") {
    cors(origin, nres, nreq.headers["access-control-request-headers"]);
    nres.writeHead(204).end();
    return;
  }
  const headers = new Headers();
  for (const [n, v] of Object.entries(nreq.headers)) if (v !== undefined) headers.set(n, Array.isArray(v) ? v.join(", ") : v);
  const hasBody = nreq.method !== "GET" && nreq.method !== "HEAD";
  const req = new Request(`http://${nreq.headers.host ?? "localhost"}${nreq.url}`, {
    method: nreq.method,
    headers,
    body: hasBody ? (Readable.toWeb(nreq) as ReadableStream) : undefined,
    duplex: "half",
  } as RequestInit);

  let res: Response;
  try { res = await route(req); } catch (e) {
    console.error("route failed", (e as Error).message);
    res = new Response("Something went wrong on our side.", { status: 500 });
  }
  cors(origin, nres);
  res.headers.forEach((v, n) => { if (n !== "content-length" && n !== "transfer-encoding") nres.setHeader(n, v); });
  nres.writeHead(res.status);
  if (!res.body) { nres.end(); return; }
  const reader = res.body.getReader();
  nres.on("close", () => { reader.cancel().catch(() => {}); });
  for (;;) {
    const { done, value } = await reader.read().catch(() => ({ done: true, value: undefined }));
    if (done) break;
    nres.write(value);
  }
  nres.end();
}

createServer((req, res) => { serve(req, res).catch(() => { if (!res.headersSent) res.writeHead(500); res.end(); }); })
  .listen(PORT, () => console.log(`paranoid gateway on ${PORT}`));
