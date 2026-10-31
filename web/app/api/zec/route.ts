// GET /api/zec: whether this gateway sells for Zcash and SOL, and the wallet that buys on the buyer's behalf.
// `shown` is whether the app offers Zcash to everyone (PARANOID_ZEC=1; before that only at /app?zec=1), `sol`
// whether it offers SOL (PARANOID_SOL=1).
// POST /api/zec {commitment, questions, refund, coin}: a one-time ZEC or SOL address for this purchase
// (lib/paranoid/zec.ts). The commitment is Poseidon(secret); the secret stays with the buyer. `refund` is where
// the coins go back if the swap cannot be done: the buyer's ZEC address (optional; without one, a refund comes to
// the gateway, which sends it back by hand), or for SOL the buyer's own wallet (required).
import { Connection, PublicKey } from "@solana/web3.js";
import { GATEWAY } from "@/lib/paranoid/server";
import { readConfig, readMembers } from "@/lib/paranoid/chain";
import { MIN_BUY } from "@/lib/paranoid/launch";
import { P } from "@/lib/paranoid/sdk";
import { SETUP_USDC } from "@/lib/paranoid/x402";
import { coinUsd, quoteZec, sealOrder, type Coin } from "@/lib/paranoid/zec";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const refuse = (status: number, message: string) => Response.json({ error: message }, { status });

export async function GET() {
  const r = GATEWAY.reporter;
  return Response.json({
    open: !!r, shown: process.env.PARANOID_ZEC === "1", sol: !!r && process.env.PARANOID_SOL === "1",
    gateway: r?.publicKey.toBase58() ?? null, fee: Number(SETUP_USDC),
    zecUsd: r ? await coinUsd("zec") : null, solUsd: r ? await coinUsd("sol") : null,
  });
}

export async function POST(req: Request) {
  const reporter = GATEWAY.reporter;
  if (!reporter) return refuse(503, "Buying with Zcash or SOL is not open on this gateway.");
  const body = (await req.json().catch(() => ({}))) as { commitment?: string; questions?: number; refund?: string; coin?: string };
  const coin: Coin = body.coin === "sol" ? "sol" : "zec";
  if (coin === "sol" && process.env.PARANOID_SOL !== "1") return refuse(503, "Buying with SOL is not open on this gateway.");
  const hex = String(body.commitment ?? "").toLowerCase().replace(/^0x/, "");
  const commitment = /^[0-9a-f]{1,64}$/.test(hex) ? BigInt("0x" + hex) : 0n;
  if (commitment <= 0n || commitment >= P) return refuse(400, "commitment must be Poseidon(secret) as hex.");
  const refund = String(body.refund ?? "").trim();
  if (coin === "sol") {
    try { new PublicKey(refund); } catch { return refuse(400, "refund must be the Solana wallet the SOL comes from."); }
  } else if (refund && !/^[a-zA-Z0-9]{20,300}$/.test(refund)) return refuse(400, "That does not look like a Zcash address. Leave it empty if you have none.");

  const conn = new Connection(GATEWAY.rpc, "confirmed");
  const cfg = await readConfig(conn, GATEWAY.programId);
  if (!cfg) return refuse(503, "PARANOID is not set up on this chain.");
  const questions = Number(body.questions);
  const m = (await readMembers(conn, GATEWAY.programId)).find((x) => x.commitment === commitment);
  // An existing membership can be topped up only by the wallet that bought it, so only one the gateway bought.
  if (m && (m.status !== "active" || !m.depositor.equals(reporter.publicKey)))
    return refuse(409, "Zcash and SOL can buy a new membership, or add to one bought with them. This one was bought another way.");
  const room = cfg.limit - (m ? m.questions : 0);
  const floor = Math.max(cfg.minQuestions, MIN_BUY);
  if (!Number.isInteger(questions) || questions < floor || questions > room)
    return refuse(400, `questions must be a whole number from ${floor} to ${room}.`);

  const usdc = BigInt(questions) * cfg.rate + SETUP_USDC;
  let q = await quoteZec(reporter.publicKey, usdc, refund, coin);
  // A refund address 1Click will not take (it may refund only to some address types): refunds come to the gateway.
  const refundDropped = coin === "zec" && !q.ok && !!refund && /refundTo/i.test(q.message);
  if (refundDropped) q = await quoteZec(reporter.publicKey, usdc, "", coin);
  if (!q.ok) return refuse(502, q.message);
  return Response.json({
    order: sealOrder(reporter, { deposit: q.quote.depositAddress, commitment, questions, usdc, coin }),
    coin,
    address: q.quote.depositAddress,
    zec: q.quote.amountInFormatted,
    amount_in: q.quote.amountIn,
    usdc: Number(usdc) / 1e6,
    minutes: Math.max(1, Math.round(q.quote.timeEstimate / 60)),
    deadline: q.quote.deadline,
    top_up: !!m,
    refund_dropped: refundDropped,
  });
}
