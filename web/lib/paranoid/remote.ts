// The server behind paranoid.red/mcp/<URL key>: PARANOID for MCP clients that can only reach a URL, such as
// Claude's custom connectors on the web and on phones. The connector proves on the member's own computer; this
// proves here, so whoever runs this server could tie a URL's questions to its membership. /mcp says so plainly
// and suggests a membership kept for the URL alone.
//
// The URL carries the member's secret sealed with PARANOID_MCP_KEY (AES-256-GCM), so the secret never shows up
// in a request log. Nothing is stored: every call unseals it, proves, asks, and lets it go. Only the tickets'
// public tags stay in memory for a while, filed under the membership's commitment.
//
// Ticket numbers. The app and the connector spend a membership's tickets from 0 upward; this server spends them
// from the top down and stops MARGIN short of where their spending has reached, so the two never pick the same
// ticket. Within this process a ticket picked by a call still on its way is reserved, so parallel calls never
// share one either. That matters because one ticket spent on two different messages reveals the secret and gets
// the membership slashed. A key refused for an old member list is proven again for the same tickets and the same
// x, which hands the gateway the very same points.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { join } from "node:path";
import { Connection } from "@solana/web3.js";
import * as snarkjs from "snarkjs";
import { commitmentOf, packKey, proveSpend, randomField, ticketNullifier, W, type Prover, type Spend } from "./sdk.ts";
import { chainNow, epochAt, readConfig, readMembers, treeOf, type Config, type Member } from "./chain.ts";
import { isSpent } from "./gateway.ts";
import { GATEWAY, pickModel } from "./server.ts";
import { POST as chat } from "@/app/api/v1/chat/completions/route";
import { GET as listModels } from "@/app/api/v1/models/route";

/** Questions this server leaves unspent between its own spending and the app's and the connector's. */
export const MARGIN = 16;
/** Unspent tickets in a row that mark how far the spending from 0 has reached. */
const RUN = 8;

const zk = (file: string) => join(process.cwd(), "public", "zk", file);
const prove: Prover = (input) => snarkjs.groth16.fullProve(input, zk("request.wasm"), zk("request.zkey")) as never;

// ---- the secret, sealed into the URL

export const mcpReady = (): boolean => /^[0-9a-f]{64}$/i.test(process.env.PARANOID_MCP_KEY ?? "");
const sealKey = () => Buffer.from(process.env.PARANOID_MCP_KEY!, "hex");

/** The secret from a connector code `<secret>.<next>`; the counter is not needed here. */
export function parseCode(text: string): bigint | null {
  const [a, b] = text.trim().split(".");
  if (!/^\d+$/.test(a ?? "") || !/^\d+$/.test(b ?? "")) return null;
  const secret = BigInt(a);
  return secret > 0n ? secret : null;
}

export function seal(secret: bigint): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", sealKey(), iv);
  const body = Buffer.concat([c.update(secret.toString(), "utf8"), c.final()]);
  return Buffer.concat([iv, body, c.getAuthTag()]).toString("base64url");
}

export function unseal(token: string): bigint | null {
  try {
    const raw = Buffer.from(token, "base64url");
    if (raw.length < 12 + 1 + 16) return null;
    const d = createDecipheriv("aes-256-gcm", sealKey(), raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(raw.length - 16));
    const text = Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]).toString("utf8");
    return /^\d+$/.test(text) && BigInt(text) > 0n ? BigInt(text) : null;
  } catch {
    return null;
  }
}

// ---- the membership, today

type Today = { cfg: Config; now: number; members: Member[]; m: Member };

/** Reads the chain for this secret's membership, or says in plain words why it cannot ask today. */
export async function today(secret: bigint): Promise<Today | string> {
  const conn = new Connection(GATEWAY.rpc, "confirmed");
  const cfg = await readConfig(conn, GATEWAY.programId);
  if (!cfg) return "PARANOID is not open on this network.";
  const [members, t] = await Promise.all([readMembers(conn, GATEWAY.programId), chainNow(conn)]);
  const m = members.find((x) => x.commitment === commitmentOf(secret));
  if (!m) return "No membership has this connector code. Check it on the Keys tab at paranoid.red/app.";
  if (m.status === "slashed") return "This membership was slashed and has no questions left.";
  const now = epochAt(cfg, t);
  if (m.endEpoch < now) return "This membership has run out of days. Top it up at paranoid.red/app.";
  return { cfg, now, members, m };
}

// ---- picking tickets

// A ticket's tag (its nullifier) takes about 0.2 ms to work out, so a membership of 65,535 questions takes
// seconds. Each membership's tags are worked out once, a slice at a time so other requests keep moving.
const TAGS = new Map<bigint, bigint[]>();
async function tagsOf(secret: bigint, questions: number): Promise<bigint[]> {
  const c = commitmentOf(secret);
  const tags = TAGS.get(c) ?? [];
  TAGS.delete(c);
  TAGS.set(c, tags);
  if (TAGS.size > 16) TAGS.delete(TAGS.keys().next().value!);
  for (let i = 0; i < questions; i++) {
    if (tags[i] !== undefined) continue;
    tags[i] = ticketNullifier(secret, i);
    if (i % 500 === 499) await new Promise((r) => setImmediate(r));
  }
  return tags;
}

const reserved = new Set<bigint>();
const free = (tag: bigint) => !isSpent(tag) && !reserved.has(tag);

/** How far the spending from 0 has reached: the first ticket of RUN unspent ones in a row. */
function frontier(tags: bigint[]): number {
  let run = 0;
  for (let i = 0; i < tags.length; i++) {
    if (isSpent(tags[i])) run = 0;
    else if (++run === RUN) return i - RUN + 1;
  }
  return tags.length;
}

/** The free tickets this URL may still spend, highest first, at most `limit` of them. */
function topFree(tags: bigint[], limit: number): number[] {
  const floor = frontier(tags) + MARGIN;
  const out: number[] = [];
  for (let i = tags.length - 1; i >= floor && out.length < limit; i--) if (free(tags[i])) out.push(i);
  return out;
}

/** Consecutive tickets go into one proof, at most W per proof. */
function runs(tickets: number[]): { start: number; weight: number }[] {
  const out: { start: number; weight: number }[] = [];
  for (const t of [...tickets].sort((a, b) => a - b)) {
    const last = out.at(-1);
    if (last && last.start + last.weight === t && last.weight < W) last.weight++;
    else out.push({ start: t, weight: 1 });
  }
  return out;
}

async function keyFor(secret: bigint, t: Today, tickets: number[], x: bigint): Promise<string> {
  const tree = treeOf(t.members);
  const spends: Spend[] = [];
  for (const r of runs(tickets)) {
    spends.push(await proveSpend({
      secret, endEpoch: t.m.endEpoch, questions: t.m.questions, leafIndex: t.m.leafIndex, tree,
      epoch: t.now, limit: t.cfg.limit, start: r.start, weight: r.weight, x,
    }, prove));
  }
  return packKey(spends);
}

// ---- the tools

export async function ask(secret: bigint, question: string, model?: string, system?: string): Promise<{ text: string; error?: true }> {
  const chosen = pickModel(model);
  const t = await today(secret);
  if (typeof t === "string") return { text: t, error: true };
  const tags = (await tagsOf(secret, t.m.questions)).slice(0, t.m.questions);
  // Picking and reserving happen in one go, with no await in between, so no other call can take the same tickets.
  const tickets = topFree(tags, chosen.cost);
  if (tickets.length < chosen.cost) {
    return { text: `This URL has fewer than ${chosen.cost} question${chosen.cost === 1 ? "" : "s"} left to spend on ${chosen.label}. Top up at paranoid.red/app, or pick a model that costs less.`, error: true };
  }
  const held = tickets.map((i) => tags[i]);
  for (const n of held) reserved.add(n);
  try {
    const x = randomField();
    const messages = [...(system ? [{ role: "system", content: system }] : []), { role: "user", content: question }];
    const body = JSON.stringify({ model: chosen.name, messages });
    let current = t;
    let res!: Response;
    for (let attempt = 0; attempt < 2; attempt++) {
      const key = await keyFor(secret, current, tickets, x);
      res = await chat(new Request("http://paranoid.internal/api/v1/chat/completions", {
        method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body,
      }));
      if (res.status !== 401) break;
      const code = ((await res.clone().json().catch(() => ({}))) as { error?: { code?: string } }).error?.code;
      if (code !== "stale_member_list") break;
      // The member list moved after the read (a purchase or a slash). Same tickets, same x, new list.
      const again = await today(secret);
      if (typeof again === "string") return { text: again, error: true };
      current = again;
    }
    const j = (await res.json().catch(() => ({}))) as { error?: { message?: string }; choices?: { message?: { content?: string } }[] };
    if (!res.ok) return { text: j.error?.message ?? `The gateway answered ${res.status}. No question was spent.`, error: true };
    return { text: j.choices?.[0]?.message?.content ?? "" };
  } finally {
    // Answered: the gateway has written them into its book. Not answered: it gave them back.
    for (const n of held) reserved.delete(n);
  }
}

export async function balance(secret: bigint): Promise<{ text: string; error?: true }> {
  const t = await today(secret);
  if (typeof t === "string") return { text: t, error: true };
  const tags = (await tagsOf(secret, t.m.questions)).slice(0, t.m.questions);
  const spent = tags.filter(isSpent).length;
  const forUrl = topFree(tags, tags.length).length;
  const until = new Date((t.cfg.genesis + (t.m.endEpoch + 1) * t.cfg.epochSeconds - 1) * 1000).toISOString().slice(0, 10);
  return {
    text: `${t.m.questions - spent} of ${t.m.questions} questions left, usable until ${until}. This URL can spend ${forUrl} of them: it keeps ${MARGIN} as a gap to the app and the connector.`,
  };
}

export async function models(): Promise<{ text: string; error?: true }> {
  const j = (await (await listModels()).json()) as { data: { id: string; label: string; cost: number; available: boolean }[] };
  const lines = j.data.map((m, i) =>
    `${m.id}: ${m.label}, ${m.cost} question${m.cost === 1 ? "" : "s"} a message${i === 0 ? " (default)" : ""}${m.available ? "" : ", not running right now"}`);
  return { text: lines.join("\n") };
}
