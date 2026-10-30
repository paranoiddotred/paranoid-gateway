// Anonymous web search for the chat. The gateway asks the Exa search API (an account of its own, so it
// is not cut off for asking often; our own SearXNG answers when no key is set or Exa fails) and reads
// the top pages, so search engines and websites see the gateway's address and never the person asking.
// Page fetches are SSRF-guarded: public http(s) hosts only, every redirect hop re-checked,
// sizes and times capped. Nothing here is logged or stored.
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const SEARX = (process.env.PARANOID_SEARCH_URL ?? "").replace(/\/$/, "");
const EXA = process.env.PARANOID_EXA_KEY ?? "";
const ALLOW_PRIVATE = process.env.PARANOID_SEARCH_ALLOW_PRIVATE === "1"; // local tests only

export const searchEnabled = () => EXA !== "" || SEARX !== "";

/** `text` is the page's words when the search service already read it (Exa, for research). */
type Hit = { title: string; url: string; snippet: string; text?: string };

async function exaSearch(q: string, count: number, read: number): Promise<Hit[]> {
  const r = await fetch("https://api.exa.ai/search", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": EXA },
    // For research Exa hands back the pages' words too (PDFs included, which the gateway cannot read).
    body: JSON.stringify({ query: q, numResults: Math.min(count, 10), type: "auto", ...(read ? { contents: { text: { maxCharacters: read } } } : {}) }),
    signal: AbortSignal.timeout(10000),
  });
  if (!r.ok) throw new Error(`exa answered ${r.status}`);
  const j = await r.json();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return ((j.results ?? []) as any[]).slice(0, count).map((x) => ({
    title: String(x.title ?? x.url ?? "").slice(0, 200),
    url: String(x.url ?? ""),
    snippet: String(x.text ?? "").replace(/\s+/g, " ").slice(0, 400),
    ...(read && x.text ? { text: String(x.text).slice(0, read) } : {}),
  })).filter((h) => /^https?:\/\//.test(h.url));
}

export async function webSearch(q: string, count = 6, read = 0): Promise<Hit[]> {
  if (EXA) {
    try { const hits = await exaSearch(q, count, read); if (hits.length || !SEARX) return hits; }
    catch (e) { if (!SEARX) throw e; }
  }
  const r = await fetch(`${SEARX}/search?format=json&q=${encodeURIComponent(q)}`, { signal: AbortSignal.timeout(8000) });
  if (!r.ok) {
    const who = ["server", "via", "x-powered-by"].map((h) => `${h}=${r.headers.get(h) ?? ""}`).join(" ");
    throw new Error(`search answered ${r.status} (${who}): ${(await r.text()).slice(0, 120).replace(/\s+/g, " ")}`);
  }
  const j = await r.json();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return ((j.results ?? []) as any[]).slice(0, count).map((x) => ({
    title: String(x.title ?? "").slice(0, 200),
    url: String(x.url ?? ""),
    snippet: String(x.content ?? "").slice(0, 400),
  })).filter((h) => /^https?:\/\//.test(h.url));
}

function privateIp(ip: string): boolean {
  if (ip.includes(":")) {
    const low = ip.toLowerCase();
    return low === "::1" || low.startsWith("fc") || low.startsWith("fd") || low.startsWith("fe80") || low.startsWith("::ffff:127.");
  }
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

async function hostIsPublic(hostname: string): Promise<boolean> {
  if (ALLOW_PRIVATE) return true;
  const ip = isIP(hostname) ? hostname : await lookup(hostname).then((r) => r.address).catch(() => "");
  return ip !== "" && !privateIp(ip);
}

/** The page as plain text, following at most three redirects with every hop checked. */
export async function fetchReadable(url: string, max = 8_000): Promise<string> {
  let u = new URL(url);
  for (let hop = 0; hop < 4; hop++) {
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    if (!(await hostIsPublic(u.hostname))) return "";
    const r = await fetch(u, {
      redirect: "manual",
      signal: AbortSignal.timeout(8000),
      headers: { "user-agent": "Mozilla/5.0 (compatible; paranoid-gateway)", accept: "text/html,text/plain" },
    });
    if (r.status >= 300 && r.status < 400) {
      const next = r.headers.get("location");
      if (!next) return "";
      u = new URL(next, u);
      continue;
    }
    if (!r.ok) return "";
    const ct = r.headers.get("content-type") ?? "";
    if (!/text\/html|text\/plain|application\/xhtml/.test(ct)) return "";
    const html = (await r.text()).slice(0, 400_000);
    return htmlToText(html).slice(0, max);
  }
  return "";
}

function htmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<\/(p|div|li|h[1-6]|tr|br)>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#39;/g, "'").replace(/&quot;/g, '"')
    .replace(/[ \t]+/g, " ")
    .replace(/\n\s*\n+/g, "\n")
    .trim();
}

/** Search plus the top pages, folded into one system message the model can cite. Null when empty.
 *  `deep` (research) reads more of more pages. */
export async function searchContext(query: string, deep = false): Promise<string | null> {
  const [count, read, each, all] = deep ? [8, 5, 7_000, 36_000] : [6, 3, 4_000, 14_000];
  const hits = await webSearch(query, count, deep ? each : 0);
  if (hits.length === 0) return null;
  const pages = await Promise.allSettled(hits.slice(0, read).map((h) => h.text ?? fetchReadable(h.url, each)));
  const parts = hits.map((h, i) => {
    const page = i < read && pages[i].status === "fulfilled" ? (pages[i] as PromiseFulfilledResult<string>).value : "";
    return `[${i + 1}] ${h.title}\n${h.url}\n${h.snippet}${page ? `\n${page}` : ""}`;
  });
  const today = new Date().toISOString().slice(0, 10);
  return `Today is ${today}. The user turned on web search; these results were fetched seconds ago. Answer from them where they help, cite like [1], and say so when they do not settle the question.\n\n${parts.join("\n\n")}`.slice(0, all);
}
