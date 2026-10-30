// The PARANOID gateway: turns an API key made of request proofs into model calls.
// It holds no accounts, no sessions and no logs. The only thing it remembers is which tickets
// (nullifiers) were ever used and on which message, which RLN needs to catch a ticket spent twice.
// Tickets never come back (v2), so that book is never pruned. A nullifier is a random-looking
// number that names no member.
// The book is also appended to a file (PARANOID_BOOK, or used-slots.log on the Railway volume), so a
// restart or redeploy cannot forget a ticket. Each line is: day, nullifier, x, y.
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { unpackKey, toSignals, commitmentOf, type Spend } from "./sdk.ts";
import { recoverSecret } from "./rln.ts";
import { verifyGroth16 } from "./groth16.ts";
import { graceSeconds } from "./grace.ts";
import { readConfig, decodeRoots, pdas, epochAt, chainNow, readMembers, treeOf, ixSlash, type Config } from "./chain.ts";

export type GatewayEnv = {
  rpc: string; programId: PublicKey;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  vkey: any;
  /** Pays the fee of slash transactions. Optional: without it, double uses are still refused and anyone can slash. */
  reporter?: Keypair;
};

type Used = { x: bigint; y: bigint; epoch: number };
type State = { used: Map<bigint, Used>; verified: Set<string>; chain?: { at: number; cfg: Config; roots: { root: bigint; validBefore: number }[]; now: number } };

const BOOK = process.env.PARANOID_BOOK ?? join(process.env.RAILWAY_VOLUME_MOUNT_PATH ?? ".paranoid", "used-slots.log");
const line = (n: bigint, u: Used) => `${u.epoch} ${n.toString(16)} ${u.x.toString(16)} ${u.y.toString(16)}\n`;

function load(): Map<bigint, Used> {
  const used = new Map<bigint, Used>();
  let text: string;
  try { text = readFileSync(BOOK, "utf8"); } catch (e) { if ((e as NodeJS.ErrnoException).code === "ENOENT") return used; throw e; }
  const lines = text.split("\n");
  lines.pop(); // empty after the last newline, or a line cut short by a crash mid-write
  for (const l of lines) {
    const [e, n, x, y] = l.split(" ");
    used.set(BigInt("0x" + n), { epoch: Number(e), x: BigInt("0x" + x), y: BigInt("0x" + y) });
  }
  return used;
}

function record(n: bigint, u: Used) {
  mkdirSync(dirname(BOOK), { recursive: true });
  appendFileSync(BOOK, line(n, u));
  state.used.set(n, u);
}

// One table per server process, shared by every route handler, reloaded from the book on start.
const g = globalThis as unknown as { __paranoid?: State };
const state: State = (g.__paranoid ??= { used: load(), verified: new Set() });

/** A claim held until the model starts to answer: `commit` writes it into the book, `release` drops it
 *  so a question nobody answered is not spent. While held, the slots count as used for every other
 *  request, so the same ticket cannot be sent twice in the meantime. */
export type Hold = { commit: () => void; release: () => void };

export type Verdict =
  | { ok: true; epoch: number; slotsLeft: number; hold?: Hold }
  | { ok: false; status: number; code: string; message: string; slashed?: string };

// `fresh` asks for a re-read unless the copy is under a quarter second old: a key made right after a
// purchase or top-up, or just after midnight, names a root or a day the cached copy has not seen yet.
async function chain(env: GatewayEnv, conn: Connection, fresh = false) {
  const c = state.chain;
  if (c && Date.now() - c.at < (fresh ? 250 : 1500)) return c;
  const cfg = await readConfig(conn, env.programId);
  if (!cfg) throw new Error("PARANOID is not initialized on this cluster");
  const tree = await conn.getAccountInfo(pdas(env.programId).tree, "confirmed");
  const read = { at: Date.now(), cfg, roots: decodeRoots(tree!.data), now: epochAt(cfg, await chainNow(conn)) };
  state.chain = read;
  return read;
}

/** Every ticket nullifier ever spent. Public: a nullifier names no member, and a member's browser
 *  finds its own among them to learn how many of its questions are used. */
export const usedNullifiers = (): bigint[] => [...state.used.keys()];
/** Whether a ticket is spent, or held by a request the model has not answered yet. */
export const isSpent = (n: bigint): boolean => state.used.has(n);

type Refusal = Extract<Verdict, { ok: false }>;
const fail = (status: number, code: string, message: string): Refusal => ({ ok: false, status, code, message });

/** Checks a key and claims `cost` unused slots from it, all or none. Called once per model request.
 *  With `hold`, the claim stays in memory until the caller commits or releases it (see Hold). */
export async function admit(env: GatewayEnv, key: string, cost = 1, hold = false): Promise<Verdict> {
  let spends: Spend[];
  try { spends = unpackKey(key); } catch (e) { return fail(401, "invalid_api_key", `This is not a PARANOID key (${(e as Error).message}). Make one at /app.`); }

  const conn = new Connection(env.rpc, "confirmed");
  const h = spends[0];
  let seen = await chain(env, conn);
  if (h.epoch > seen.now || !seen.roots.some((r) => r.root === h.root)) seen = await chain(env, conn, true);
  const { cfg, roots, now } = seen;
  // A key from the day that just ended still works for a short grace, so a key made in the last
  // minutes of a day is not dead on arrival.
  const late = h.epoch === now - 1 && (await chainNow(conn)) < cfg.genesis + now * cfg.epochSeconds + graceSeconds(cfg);
  if (h.epoch !== now && !late) return fail(401, "key_expired", `This key was made for day ${h.epoch}; it is day ${now} now. Make a new key at /app.`);
  if (h.limit !== cfg.limit) return fail(401, "invalid_api_key", "This key was made for different launch settings. Make a new key at /app.");
  const entry = roots.find((r) => r.root === h.root);
  if (!entry || h.epoch >= entry.validBefore) return fail(401, "stale_member_list", "This key was made against an old member list. Make a new key at /app.");

  for (const s of spends) {
    const id = toSignals(s).join(",");
    if (!state.verified.has(id)) {
      if (!verifyGroth16(env.vkey, toSignals(s), s.proof)) return fail(401, "invalid_proof", "A proof in this key does not check out.");
      state.verified.add(id);
    }
  }

  // Walk the key's tickets in order: the first `cost` ones not used yet pay for this request.
  const unused: { n: bigint; x: bigint; y: bigint; epoch: number }[] = [];
  for (const s of spends) {
    for (let j = 0; j < s.weight; j++) {
      const n = s.nullifiers[j];
      const seen = state.used.get(n);
      if (seen && seen.x !== s.x) {
        // The same ticket on two different messages: two points of one line. The member's secret falls out.
        const secret = recoverSecret(seen.x, seen.y, s.x, s.ys[j]);
        const sig = await slash(env, conn, cfg, secret).catch((e) => `not sent (${(e as Error).message})`);
        return { ...fail(402, "slot_reused", "This key spends a ticket that was already spent on another message. The member who made it has been slashed and lost every ticket it had left."), slashed: sig };
      }
      if (!seen) unused.push({ n, x: s.x, y: s.ys[j], epoch: s.epoch });
    }
  }
  if (unused.length === 0) return fail(402, "key_used_up", "Every ticket in this key is spent. Make a new key at /app.");
  if (unused.length < cost) return fail(402, "key_too_small", `This model takes ${cost} questions a message and this key has ${unused.length} left. Make a new key at /app.`);
  const claimed = unused.slice(0, cost);
  if (!hold) {
    for (const u of claimed) record(u.n, { x: u.x, y: u.y, epoch: u.epoch });
    return { ok: true, epoch: now, slotsLeft: unused.length - cost };
  }
  for (const u of claimed) state.used.set(u.n, { x: u.x, y: u.y, epoch: u.epoch });
  let done = false;
  return {
    ok: true, epoch: now, slotsLeft: unused.length - cost,
    hold: {
      commit: () => { if (done) return; done = true; for (const u of claimed) record(u.n, state.used.get(u.n)!); },
      release: () => { if (done) return; done = true; for (const u of claimed) state.used.delete(u.n); },
    },
  };
}

/** Anyone may slash with a recovered secret; the gateway does it at once so the cheat costs real money. */
async function slash(env: GatewayEnv, conn: Connection, cfg: Config, secret: bigint): Promise<string> {
  if (!env.reporter) return "no reporter key configured";
  const members = await readMembers(conn, env.programId);
  const commitment = commitmentOf(secret);
  const m = members.find((x) => x.commitment === commitment);
  if (!m) throw new Error("member not found");
  if (m.status === "slashed") return "already slashed";
  const tx = new Transaction().add(ixSlash(env.programId, cfg, env.reporter.publicKey, m, treeOf(members), secret));
  tx.feePayer = env.reporter.publicKey;
  tx.recentBlockhash = (await conn.getLatestBlockhash("confirmed")).blockhash;
  tx.sign(env.reporter);
  const sig = await conn.sendRawTransaction(tx.serialize());
  await conn.confirmTransaction(sig, "confirmed");
  state.chain = undefined;
  return sig;
}
