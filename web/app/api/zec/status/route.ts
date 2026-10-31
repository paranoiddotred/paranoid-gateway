// GET /api/zec/status?order=<order>: where a Zcash or SOL purchase stands. Once the swap has paid the gateway in USDC,
// the first call that sees it buys the questions (or tops up a membership the gateway bought before), and every
// later call gets the same answer. Calling it is safe at any time and from anywhere.
import { Connection, Transaction } from "@solana/web3.js";
import { GATEWAY } from "@/lib/paranoid/server";
import { ixDeposit, ixTopUp, pdas, readConfig, readMembers, treeOf } from "@/lib/paranoid/chain";
import { base58, bought, claim, record, unclaim } from "@/lib/paranoid/x402";
import { inFlight, openOrder, received, setFlight, swapOf } from "@/lib/paranoid/zec";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const refuse = (status: number, message: string) => Response.json({ error: message }, { status });

export async function GET(req: Request) {
  const reporter = GATEWAY.reporter;
  if (!reporter) return refuse(503, "Buying with Zcash or SOL is not open on this gateway.");
  const o = openOrder(reporter, new URL(req.url).searchParams.get("order") ?? "");
  if (!o) return refuse(400, "This is not an order from this gateway.");
  const id = `zec:${o.deposit}`;
  const hex = o.commitment.toString(16);
  const done = (b: { questions: number; deposit: string }) =>
    Response.json({ state: "done", questions: b.questions, member: pdas(GATEWAY.programId).member(o.commitment).toBase58(), deposit: b.deposit });

  const before = bought(id);
  if (before) return done(before);
  const swap = await swapOf(o, reporter.publicKey);
  if (swap.state !== "paid") return Response.json(swap);

  const conn = new Connection(GATEWAY.rpc, "confirmed");
  const cfg = await readConfig(conn, GATEWAY.programId);
  if (!cfg) return refuse(503, "PARANOID is not set up on this chain.");
  const need = BigInt(o.questions) * cfg.rate;
  const got = await received(conn, swap.tx, reporter.publicKey);
  if (got < need) return Response.json({ state: "swapping" }); // the payout is not readable on chain yet

  if (!claim(id)) return Response.json({ state: "swapping" });
  if (!claim(hex)) { unclaim(id); return Response.json({ state: "swapping" }); }
  try {
    // A purchase sent earlier whose confirmation was lost: settle by what the chain says about it.
    const f = inFlight(id);
    if (f) {
      const st = (await conn.getSignatureStatus(f.sig, { searchTransactionHistory: true })).value;
      if (st && !st.err) {
        if (st.confirmationStatus === "processed") return Response.json({ state: "swapping" });
        record(id, o.commitment, o.questions, f.sig); setFlight(id, null); return done({ questions: o.questions, deposit: f.sig });
      }
      if (!st && (await conn.getBlockHeight("confirmed")) <= f.lastValid) return Response.json({ state: "swapping" });
      setFlight(id, null); // failed or expired: it bought nothing, so buy now
    }
    const members = await readMembers(conn, GATEWAY.programId);
    const m = members.find((x) => x.commitment === o.commitment);
    if (m && !(m.status === "active" && m.depositor.equals(reporter.publicKey)))
      return Response.json({ state: "failed", reason: "This membership can no longer take questions. Write to us on X with this order to be paid back." });
    const tx = new Transaction().add(m ? ixTopUp(GATEWAY.programId, reporter.publicKey, m, treeOf(members), o.questions) : ixDeposit(GATEWAY.programId, reporter.publicKey, o.commitment, o.questions));
    const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
    tx.feePayer = reporter.publicKey;
    tx.recentBlockhash = blockhash;
    tx.sign(reporter);
    const sig = base58(tx.signature!);
    setFlight(id, { sig, lastValid: lastValidBlockHeight });
    await conn.sendRawTransaction(tx.serialize());
    const r = await conn.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, "confirmed").catch(() => null);
    if (!r) return Response.json({ state: "swapping" }); // the next call reads the outcome
    setFlight(id, null);
    if (r.value.err) { console.error("zec purchase failed", o.deposit, JSON.stringify(r.value.err)); return Response.json({ state: "swapping" }); }
    record(id, o.commitment, o.questions, sig);
    return done({ questions: o.questions, deposit: sig });
  } finally {
    unclaim(id);
    unclaim(hex);
  }
}
