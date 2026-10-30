// POST /api/x402/join?questions=<n>&commitment=<hex>: buys a PARANOID membership with an x402 payment (lib/paranoid/x402.ts).
// Without a payment header it answers 402 with the price. With PAYMENT-SIGNATURE (x402 v2) or X-PAYMENT (v1) it checks
// the payment, adds the gateway's fee payer signature, sends it, then buys the questions for the commitment.
// The commitment is Poseidon(secret); the secret never leaves the agent, so only the agent can spend these questions.
import { Connection } from "@solana/web3.js";
import { GATEWAY } from "@/lib/paranoid/server";
import { pdas, readConfig } from "@/lib/paranoid/chain";
import { P } from "@/lib/paranoid/sdk";
import { base58, bought, checkPayment, claim, deposit, memoFor, networkOf, requirements, SETUP_USDC, unclaim } from "@/lib/paranoid/x402";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");
const refuse = (status: number, message: string) => Response.json({ error: message }, { status });

export async function POST(req: Request) {
  const reporter = GATEWAY.reporter;
  if (!reporter) return refuse(503, "Buying with x402 is not open on this gateway.");
  const url = new URL(req.url);
  const questions = Number(url.searchParams.get("questions"));
  const hex = (url.searchParams.get("commitment") ?? "").toLowerCase().replace(/^0x/, "");
  const commitment = /^[0-9a-f]{1,64}$/.test(hex) ? BigInt("0x" + hex) : 0n;
  if (commitment <= 0n || commitment >= P) return refuse(400, "commitment must be Poseidon(secret) as hex, a number below the BN254 field size.");

  const conn = new Connection(GATEWAY.rpc, "confirmed");
  const cfg = await readConfig(conn, GATEWAY.programId);
  if (!cfg) return refuse(503, "PARANOID is not set up on this chain.");
  if (!Number.isInteger(questions) || questions < cfg.minQuestions || questions > cfg.limit)
    return refuse(400, `questions must be a whole number from ${cfg.minQuestions} to ${cfg.limit}.`);

  const amount = BigInt(questions) * cfg.rate + SETUP_USDC;
  const memo = memoFor(commitment, questions);
  const network = await networkOf(conn);
  const self = `${process.env.PARANOID_SELF_URL ?? url.origin}/api/x402/join?questions=${questions}&commitment=${hex}`;
  const { accepted, resource } = requirements(network, reporter.publicKey, amount, memo, self);
  const askToPay = (error: string, extra: Record<string, string> = {}) =>
    Response.json(
      // The body is the v1 form, for clients that read it there; v2 clients read the header.
      { x402Version: 1, error, accepts: [{ ...accepted, network: network === "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" ? "solana" : network, maxAmountRequired: accepted.amount, resource: self, description: resource.description, mimeType: resource.mimeType }] },
      { status: 402, headers: { "payment-required": b64({ x402Version: 2, error, resource, accepts: [accepted] }), ...extra } },
    );

  const header = req.headers.get("payment-signature") ?? req.headers.get("x-payment");
  if (!header) return askToPay("PAYMENT-SIGNATURE header is required");
  let tx64: unknown;
  try { tx64 = JSON.parse(Buffer.from(header, "base64").toString("utf8"))?.payload?.transaction; } catch { /* checked below */ }
  if (typeof tx64 !== "string") return refuse(400, "The payment header is not an x402 payment payload.");
  const check = checkPayment(tx64, reporter.publicKey, amount, memo);
  const settled = (success: boolean, transaction: string, errorReason?: string) =>
    b64({ success, transaction, network, payer: check.ok ? check.payer.toBase58() : "", ...(errorReason ? { errorReason } : {}) });
  if (!check.ok) return askToPay(check.reason, { "payment-response": settled(false, "", check.reason) });

  const { tx } = check;
  tx.sign([reporter]);
  const payment = base58(tx.signatures[0]);
  const done = (b: { questions: number; deposit: string }) =>
    Response.json(
      { commitment: hex, questions: b.questions, member: pdas(GATEWAY.programId).member(commitment).toBase58(), payment, deposit: b.deposit },
      { headers: { "payment-response": settled(true, payment) } },
    );

  // A retry of a payment that already bought its questions gets the same answer again.
  const before = bought(payment);
  if (before) return done(before);
  if (!claim(payment)) return refuse(409, "This payment is being settled already.");
  if (!claim(hex)) { unclaim(payment); return refuse(409, "This commitment is being bought already."); }
  try {
    const landed = (await conn.getSignatureStatus(payment, { searchTransactionHistory: true })).value;
    if (!landed) {
      if (await conn.getAccountInfo(pdas(GATEWAY.programId).member(commitment))) return refuse(409, "This commitment is a member already. Make a new secret for a new membership.");
      const sim = await conn.simulateTransaction(tx, { sigVerify: true, commitment: "confirmed" });
      if (sim.value.err) console.error("x402 simulation failed", JSON.stringify(sim.value.err), sim.value.logs?.slice(-3).join(" | "));
      if (sim.value.err) return askToPay("simulation_failed", { "payment-response": settled(false, "", "simulation_failed") });
      await conn.sendRawTransaction(tx.serialize(), { skipPreflight: true });
      const r = await conn.confirmTransaction(payment, "confirmed");
      if (r.value.err) return askToPay("transaction_failed", { "payment-response": settled(false, payment, "transaction_failed") });
    } else if (landed.err) return askToPay("transaction_failed", { "payment-response": settled(false, payment, "transaction_failed") });

    // Paid. Buy the questions; a failure here is finished by sending the same request again.
    let last: unknown;
    for (let i = 0; i < 3; i++) {
      try { return done({ questions, deposit: await deposit(conn, GATEWAY.programId, reporter, payment, commitment, questions) }); }
      catch (e) { last = e; await new Promise((r) => setTimeout(r, 1500)); }
    }
    console.error("x402 deposit failed", payment, (last as Error)?.message);
    return refuse(500, `Your payment ${payment} landed, but the membership could not be written just now. Send the same request again to finish it.`);
  } finally {
    unclaim(payment);
    unclaim(hex);
  }
}
