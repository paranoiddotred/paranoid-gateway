// Buying questions with x402 (https://github.com/coinbase/x402, scheme `exact` on Solana), so an agent with
// nothing but a wallet can join without the site. The agent makes its secret itself and sends only the
// commitment; it pays USDC to the gateway's wallet in an ordinary x402 payment, and the gateway then buys the
// questions for that commitment on chain. The membership's depositor is the gateway, not the agent's wallet.
//
// The gateway sponsors the payment's network fee, so before signing it checks the transaction as the scheme's
// Sponsor Acceptance Policy asks: the fee payer appears in no instruction, only compute budget, one
// TransferChecked, memo and Lighthouse instructions, exactly one transfer of at least the price to the gateway's
// USDC account, and a memo that binds the payment to the commitment and the number of questions.
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { ComputeBudgetProgram, Connection, Keypair, PublicKey, Transaction, VersionedTransaction } from "@solana/web3.js";
import { ata, ixDeposit, TOKEN_PROGRAM, USDC_MINT } from "./chain.ts";

/** Paid on top of the questions: the gateway pays rent for the new member account (about 0.0011 SOL) and two network fees. */
export const SETUP_USDC = 300_000n;
const MEMO = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const LIGHTHOUSE = new PublicKey("L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95");
const MAX_UNITS = 400_000;
const MAX_MICROLAMPORTS = 5_000_000; // 5 lamports a unit, the scheme's static path cap

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/** Base58, the spelling Solana uses for transaction signatures. */
export function base58(b: Uint8Array) {
  let n = BigInt("0x" + (Buffer.from(b).toString("hex") || "0")), s = "";
  while (n > 0n) { s = ALPHABET[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x) break; s = "1" + s; }
  return s;
}

/** The memo the payment must carry: it ties the money to this commitment and this many questions. 32 characters, the
 *  length of the random memo standard clients write, so it fits their compute budget (20,000 units in @x402/svm). */
export const memoFor = (commitment: bigint, questions: number) =>
  createHash("sha256").update(`paranoid:${commitment.toString(16)}:${questions}`).digest("hex").slice(0, 32);

let network: string | undefined;
/** CAIP-2 name of the chain the gateway reads: "solana:" and the first 32 characters of its genesis hash. */
export async function networkOf(conn: Connection) {
  return (network ??= "solana:" + (await conn.getGenesisHash()).slice(0, 32));
}

export function requirements(net: string, reporter: PublicKey, amount: bigint, memo: string, url: string) {
  const accepted = {
    scheme: "exact", network: net, amount: amount.toString(), asset: USDC_MINT.toBase58(), payTo: reporter.toBase58(),
    maxTimeoutSeconds: 60, extra: { feePayer: reporter.toBase58(), memo },
  };
  const resource = { url, description: "A PARANOID membership: questions to any of its AI models, each one unlinkable from the others", mimeType: "application/json" };
  return { accepted, resource };
}

type Check = { ok: true; tx: VersionedTransaction; payer: PublicKey } | { ok: false; reason: string };

/** Checks a client's partly signed payment before the gateway adds its fee payer signature. */
export function checkPayment(b64: string, reporter: PublicKey, amount: bigint, memo: string): Check {
  let tx: VersionedTransaction;
  try { tx = VersionedTransaction.deserialize(Buffer.from(b64, "base64")); } catch { return { ok: false, reason: "invalid_transaction" }; }
  const m = tx.message;
  if (m.addressTableLookups.length) return { ok: false, reason: "address_lookup_tables_not_supported" };
  const keys = m.staticAccountKeys;
  if (!keys[0]?.equals(reporter)) return { ok: false, reason: "invalid_fee_payer" };
  if (m.header.numRequiredSignatures !== 2) return { ok: false, reason: "invalid_signer_count" };
  const ixs = m.compiledInstructions;
  if (ixs.length < 3 || ixs.length > 7) return { ok: false, reason: "invalid_instruction_count" };

  let transfers = 0, memos = 0, payer: PublicKey | undefined;
  for (const ix of ixs) {
    const program = keys[ix.programIdIndex];
    // Fee payer isolation: the gateway's key pays the network fee and nothing else.
    if (ix.accountKeyIndexes.some((i) => keys[i].equals(reporter))) return { ok: false, reason: "fee_payer_in_instruction" };
    const d = ix.data;
    if (program.equals(ComputeBudgetProgram.programId)) {
      if (d[0] === 2 && d.length === 5 && Buffer.from(d).readUInt32LE(1) <= MAX_UNITS) continue;
      if (d[0] === 3 && d.length === 9 && Buffer.from(d).readBigUInt64LE(1) <= BigInt(MAX_MICROLAMPORTS)) continue;
      return { ok: false, reason: "invalid_compute_budget" };
    }
    if (program.equals(TOKEN_PROGRAM)) {
      // TransferChecked: [12, amount u64, decimals u8], accounts source, mint, destination, authority.
      if (d[0] !== 12 || d.length !== 10 || ix.accountKeyIndexes.length < 4) return { ok: false, reason: "invalid_token_instruction" };
      const [source, mint, dest, authority] = ix.accountKeyIndexes.map((i) => keys[i]);
      if (!mint.equals(USDC_MINT) || d[9] !== 6) return { ok: false, reason: "invalid_mint" };
      if (!dest.equals(ata(reporter))) return { ok: false, reason: "invalid_recipient" };
      if (Buffer.from(d).readBigUInt64LE(1) < amount) return { ok: false, reason: "invalid_amount" };
      if (source.equals(ata(reporter))) return { ok: false, reason: "self_payment" };
      payer = authority;
      transfers++;
      continue;
    }
    if (program.equals(MEMO)) {
      if (Buffer.from(d).toString("utf8") !== memo) return { ok: false, reason: "invalid_memo" };
      memos++;
      continue;
    }
    if (program.equals(LIGHTHOUSE)) continue;
    return { ok: false, reason: "program_not_allowed" };
  }
  if (transfers !== 1) return { ok: false, reason: "invalid_transfer_count" };
  if (memos !== 1) return { ok: false, reason: "invalid_memo" };
  // The only other required signer is the one who pays.
  if (!keys[1].equals(payer!)) return { ok: false, reason: "invalid_signer" };
  return { ok: true, tx, payer: payer! };
}

// ---- payments that bought a membership, so one payment never buys twice and a retry finishes the job

const BOOK = process.env.PARANOID_X402_BOOK ?? join(process.env.RAILWAY_VOLUME_MOUNT_PATH ?? ".paranoid", "x402.log");
type Bought = { commitment: bigint; questions: number; deposit: string };
const g = globalThis as unknown as { __paranoidX402?: { book: Map<string, Bought>; busy: Set<string> } };
const state = (g.__paranoidX402 ??= { book: load(), busy: new Set() });

function load() {
  const book = new Map<string, Bought>();
  let text = "";
  try { text = readFileSync(BOOK, "utf8"); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
  for (const l of text.split("\n").slice(0, -1)) {
    const [payment, c, q, deposit] = l.split(" ");
    book.set(payment, { commitment: BigInt("0x" + c), questions: Number(q), deposit });
  }
  return book;
}

export const bought = (payment: string) => state.book.get(payment);

/** Claims a payment while it is being settled, so two copies of one request cannot both go through. */
export function claim(payment: string) {
  if (state.busy.has(payment)) return false;
  state.busy.add(payment);
  return true;
}
export const unclaim = (payment: string) => state.busy.delete(payment);

/** Buys the questions for the commitment from the gateway's wallet and writes the payment into the book. */
export async function deposit(conn: Connection, programId: PublicKey, reporter: Keypair, payment: string, commitment: bigint, questions: number) {
  const tx = new Transaction().add(ixDeposit(programId, reporter.publicKey, commitment, questions));
  tx.feePayer = reporter.publicKey;
  tx.recentBlockhash = (await conn.getLatestBlockhash("confirmed")).blockhash;
  tx.sign(reporter);
  const sig = await conn.sendRawTransaction(tx.serialize());
  const r = await conn.confirmTransaction(sig, "confirmed");
  if (r.value.err) throw new Error(`deposit failed: ${JSON.stringify(r.value.err)}`);
  record(payment, commitment, questions, sig);
  return sig;
}

/** Writes a payment that bought its questions into the book. */
export function record(payment: string, commitment: bigint, questions: number, sig: string) {
  mkdirSync(dirname(BOOK), { recursive: true });
  appendFileSync(BOOK, `${payment} ${commitment.toString(16)} ${questions} ${sig}\n`);
  state.book.set(payment, { commitment, questions, deposit: sig });
}
