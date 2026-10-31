// Buying questions with Zcash or SOL. The buyer sends ZEC (ideally from a shielded address) or SOL to a one-time
// address from NEAR Intents 1Click (https://docs.near-intents.org), which swaps it into USDC on Solana and pays it
// to the gateway's wallet. The gateway then buys the questions for the buyer's commitment, as it does for x402,
// so on Solana the membership's depositor is the gateway and on Zcash a shielded sender shows no one.
//
// An order is the 1Click deposit address plus the commitment and number of questions it pays for, sealed
// with an HMAC under the gateway's key so a deposit address cannot be pointed at another commitment.
import { createHmac, timingSafeEqual } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { ata, USDC_MINT } from "./chain.ts";

export const ONECLICK = process.env.PARANOID_ONECLICK_URL ?? "https://1click.chaindefuser.com/v0";
export const ZEC_ASSET = "nep141:zec.omft.near";
export const SOL_ASSET = "nep141:sol.omft.near";
export const USDC_SOL_ASSET = "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near";

export type Coin = "zec" | "sol";
export const ASSET: Record<Coin, string> = { zec: ZEC_ASSET, sol: SOL_ASSET };
export type Order = { deposit: string; commitment: bigint; questions: number; usdc: bigint; coin: Coin };

const b64u = (b: Buffer) => b.toString("base64url");
const mac = (key: Keypair, body: string) => createHmac("sha256", key.secretKey).update("paranoid-zec:" + body).digest();

export function sealOrder(key: Keypair, o: Order): string {
  const body = b64u(Buffer.from(JSON.stringify({ d: o.deposit, c: o.commitment.toString(16), q: o.questions, u: o.usdc.toString(), a: o.coin })));
  return `${body}.${b64u(mac(key, body))}`;
}

export function openOrder(key: Keypair, token: string): Order | null {
  const [body, tag] = token.split(".");
  if (!body || !tag) return null;
  const want = mac(key, body), got = Buffer.from(tag, "base64url");
  if (got.length !== want.length || !timingSafeEqual(got, want)) return null;
  try {
    const j = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return { deposit: String(j.d), commitment: BigInt("0x" + j.c), questions: Number(j.q), usdc: BigInt(j.u), coin: j.a === "sol" ? "sol" : "zec" };
  } catch { return null; }
}

const prices: Partial<Record<Coin, { usd: number; at: number }>> = {};
/** A coin in US dollars from 1Click's token list, at most a minute old, for showing about how much a pack takes. */
export async function coinUsd(coin: Coin): Promise<number | null> {
  const had = prices[coin];
  if (had && Date.now() - had.at < 60_000) return had.usd;
  try {
    const list = (await (await fetch(`${ONECLICK}/tokens`, { cache: "no-store" })).json()) as { assetId: string; price?: number }[];
    for (const c of Object.keys(ASSET) as Coin[]) {
      const usd = Number(list.find((t) => t.assetId === ASSET[c])?.price);
      if (usd > 0) prices[c] = { usd, at: Date.now() };
    }
  } catch { /* keep the last price */ }
  return prices[coin]?.usd ?? null;
}

type Quote = { depositAddress: string; amountIn: string; amountInFormatted: string; deadline: string; timeEstimate: number };

/** Asks 1Click for a deposit address in `coin` that pays exactly `usdc` (base units) to `recipient` on Solana.
 *  Without a refund address, a failed swap refunds to the gateway's own NEAR Intents account: the NEAR implicit
 *  account of the same ed25519 key, so the gateway can send it back by hand. */
export async function quoteZec(recipient: PublicKey, usdc: bigint, refundTo: string, coin: Coin = "zec"): Promise<{ ok: true; quote: Quote } | { ok: false; message: string }> {
  const refund = refundTo
    ? { refundTo, refundType: "ORIGIN_CHAIN" }
    : { refundTo: Buffer.from(recipient.toBytes()).toString("hex"), refundType: "INTENTS" };
  const res = await fetch(`${ONECLICK}/quote`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      dry: false, swapType: "EXACT_OUTPUT", slippageTolerance: 100,
      originAsset: ASSET[coin], depositType: "ORIGIN_CHAIN", amount: usdc.toString(),
      destinationAsset: USDC_SOL_ASSET, recipient: recipient.toBase58(), recipientType: "DESTINATION_CHAIN",
      ...refund,
      deadline: new Date(Date.now() + 3_600_000).toISOString(),
    }),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok || !j.quote?.depositAddress) return { ok: false, message: String(j.message ?? `The swap service answered ${res.status}.`) };
  return { ok: true, quote: j.quote };
}

export type Swap =
  | { state: "waiting" | "swapping" }
  | { state: "failed"; reason: string }
  | { state: "paid"; usdc: bigint; tx: string };

/** Where the swap behind a deposit address stands. `paid` only when 1Click says it finished for this very
 *  order (ZEC in, USDC on Solana out, to the gateway) and gives the Solana transaction that paid. */
export async function swapOf(o: Order, recipient: PublicKey): Promise<Swap> {
  const res = await fetch(`${ONECLICK}/status?depositAddress=${encodeURIComponent(o.deposit)}`, { cache: "no-store" });
  if (!res.ok) return { state: "waiting" };
  const j = await res.json();
  const req = j.quoteResponse?.quoteRequest ?? {};
  if (req.recipient !== recipient.toBase58() || req.destinationAsset !== USDC_SOL_ASSET || req.originAsset !== ASSET[o.coin])
    return { state: "failed", reason: "This deposit address belongs to a different swap." };
  switch (j.status) {
    case "PENDING_DEPOSIT": return { state: "waiting" };
    case "KNOWN_DEPOSIT_TX": case "PROCESSING": return { state: "swapping" };
    case "SUCCESS": {
      const tx = j.swapDetails?.destinationChainTxHashes?.[0]?.hash;
      return tx ? { state: "paid", usdc: BigInt(j.swapDetails.amountOut ?? 0), tx } : { state: "swapping" };
    }
    case "REFUNDED": return { state: "failed", reason: req.refundType === "INTENTS"
      ? `The swap could not be done, so the ${o.coin.toUpperCase()} came back to PARANOID. Write to us on X with this address and we send it back.`
      : o.coin === "sol" ? "The swap could not be done, so the SOL was sent back to your wallet."
      : "The swap could not be done, so the ZEC was sent back to your refund address." };
    case "INCOMPLETE_DEPOSIT": return { state: "failed", reason: `Less ${o.coin.toUpperCase()} arrived than the order needs. Send the rest to the same address, or wait for the refund.` };
    default: return { state: "failed", reason: `The swap stopped (${j.status}).` };
  }
}

/** USDC the gateway's account received in one Solana transaction, read from the chain itself. */
export async function received(conn: Connection, sig: string, owner: PublicKey): Promise<bigint> {
  const t = await conn.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
  if (!t?.meta || t.meta.err) return 0n;
  const keys = t.transaction.message.getAccountKeys({ accountKeysFromLookups: t.meta.loadedAddresses }).keySegments().flat();
  const at = keys.findIndex((k) => k.equals(ata(owner)));
  const amt = (list: typeof t.meta.preTokenBalances) =>
    BigInt(list?.find((b) => b.accountIndex === at && b.mint === USDC_MINT.toBase58())?.uiTokenAmount.amount ?? "0");
  return at < 0 ? 0n : amt(t.meta.postTokenBalances) - amt(t.meta.preTokenBalances);
}

// ---- purchases in flight. The gateway writes a purchase's signature here before sending it, so a call that
// comes after a lost confirmation finds that transaction instead of buying a second time.

const PENDING = join(process.env.RAILWAY_VOLUME_MOUNT_PATH ?? ".paranoid", "zec-pending.log");
type Flight = { sig: string; lastValid: number };
const g = globalThis as unknown as { __paranoidZec?: Map<string, Flight> };
const flights = (g.__paranoidZec ??= loadFlights());

function loadFlights() {
  const m = new Map<string, Flight>();
  let text = "";
  try { text = readFileSync(PENDING, "utf8"); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
  for (const l of text.split("\n").slice(0, -1)) {
    const [id, sig, lastValid] = l.split(" ");
    if (sig === "-") m.delete(id); else m.set(id, { sig, lastValid: Number(lastValid) });
  }
  return m;
}

export const inFlight = (id: string) => flights.get(id);
export function setFlight(id: string, f: Flight | null) {
  mkdirSync(dirname(PENDING), { recursive: true });
  appendFileSync(PENDING, f ? `${id} ${f.sig} ${f.lastValid}\n` : `${id} - 0\n`);
  if (f) flights.set(id, f); else flights.delete(id);
}
