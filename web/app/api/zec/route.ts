// GET /api/zec: whether this gateway sells for Zcash, and the wallet that buys on the buyer's behalf. `shown` is
// whether the app offers it to everyone (PARANOID_ZEC=1); before that the app shows it only at /app?zec=1.
// POST /api/zec {commitment, questions, refund}: a one-time Zcash address for this purchase (lib/paranoid/zec.ts).
// The commitment is Poseidon(secret); the secret stays with the buyer. `refund` is the buyer's ZEC address, used
// only if the swap cannot be done; without one, a refund comes to the gateway, which sends it back by hand.
import { Connection } from "@solana/web3.js";
import { GATEWAY } from "@/lib/paranoid/server";
import { readConfig, readMembers } from "@/lib/paranoid/chain";
import { MIN_BUY } from "@/lib/paranoid/launch";
import { P } from "@/lib/paranoid/sdk";
import { SETUP_USDC } from "@/lib/paranoid/x402";
import { quoteZec, sealOrder, zecUsd } from "@/lib/paranoid/zec";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const refuse = (status: number, message: string) => Response.json({ error: message }, { status });

export async function GET() {
  const r = GATEWAY.reporter;
  return Response.json({ open: !!r, shown: process.env.PARANOID_ZEC === "1", gateway: r?.publicKey.toBase58() ?? null, fee: Number(SETUP_USDC), zecUsd: r ? await zecUsd() : null });
}

export async function POST(req: Request) {
  const reporter = GATEWAY.reporter;
  if (!reporter) return refuse(503, "Buying with Zcash is not open on this gateway.");
  const body = (await req.json().catch(() => ({}))) as { commitment?: string; questions?: number; refund?: string };
  const hex = String(body.commitment ?? "").toLowerCase().replace(/^0x/, "");
  const commitment = /^[0-9a-f]{1,64}$/.test(hex) ? BigInt("0x" + hex) : 0n;
  if (commitment <= 0n || commitment >= P) return refuse(400, "commitment must be Poseidon(secret) as hex.");
  const refund = String(body.refund ?? "").trim();
  if (refund && !/^[a-zA-Z0-9]{20,300}$/.test(refund)) return refuse(400, "That does not look like a Zcash address. Leave it empty if you have none.");

  const conn = new Connection(GATEWAY.rpc, "confirmed");
  const cfg = await readConfig(conn, GATEWAY.programId);
  if (!cfg) return refuse(503, "PARANOID is not set up on this chain.");
  const questions = Number(body.questions);
  const m = (await readMembers(conn, GATEWAY.programId)).find((x) => x.commitment === commitment);
  // An existing membership can be topped up only by the wallet that bought it, so only one the gateway bought.
  if (m && (m.status !== "active" || !m.depositor.equals(reporter.publicKey)))
    return refuse(409, "Zcash can buy a new membership, or add to one bought with Zcash. This one was bought another way.");
  const room = cfg.limit - (m ? m.questions : 0);
  const floor = Math.max(cfg.minQuestions, MIN_BUY);
  if (!Number.isInteger(questions) || questions < floor || questions > room)
    return refuse(400, `questions must be a whole number from ${floor} to ${room}.`);

  const usdc = BigInt(questions) * cfg.rate + SETUP_USDC;
  let q = await quoteZec(reporter.publicKey, usdc, refund);
  // A refund address 1Click will not take (it may refund only to some address types): refunds come to the gateway.
  const refundDropped = !q.ok && !!refund && /refundTo/i.test(q.message);
  if (refundDropped) q = await quoteZec(reporter.publicKey, usdc, "");
  if (!q.ok) return refuse(502, q.message);
  return Response.json({
    order: sealOrder(reporter, { deposit: q.quote.depositAddress, commitment, questions, usdc }),
    address: q.quote.depositAddress,
    zec: q.quote.amountInFormatted,
    usdc: Number(usdc) / 1e6,
    minutes: Math.max(1, Math.round(q.quote.timeEstimate / 60)),
    deadline: q.quote.deadline,
    top_up: !!m,
    refund_dropped: refundDropped,
  });
}
