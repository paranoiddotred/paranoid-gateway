// Reads PARANOID's accounts and builds its instructions with plain @solana/web3.js.
// Layouts mirror engine/programs/paranoid/src/state.rs; discriminators are sha256("global:<ix>")[..8].
import { PublicKey, TransactionInstruction, SystemProgram, Connection, type AccountInfo } from "@solana/web3.js";
import { buildTree, leafOf, bytesToField, fieldToBytes, type Tree } from "./sdk.ts";

export const TOKEN_PROGRAM = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const ATA_PROGRAM = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

const hex = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
const IX = {
  deposit: hex("f223c68952e1f2b6"),
  top_up: hex("ece160093c6a4dd0"),
  slash: hex("cc8d12a108b15c8e"),
  deposit_token: hex("0b9c60da27a3b413"),
  top_up_token: hex("6c06376674602ec4"),
  open_order: hex("ce58588f268832e0"),
  settle_order: hex("504acc220cb74242"),
  start_stake: hex("9d122fa22e18000b"),
  add_stake: hex("3a87bd69a078a5e0"),
  withdraw_stake: hex("9908168a69b05742"),
  return_legacy_stake: hex("539aef2a508fbe84"),
  request_unstake: hex("2c9a6efda0ca3622"),
  claim_stake_reward: hex("3b9673ee24429c1b"),
};
const DISC = { config: "9b0caae01efacc82", member: "3613a2151da611c6" };

export function pdas(programId: PublicKey) {
  const p = (...s: Uint8Array[]) => PublicKey.findProgramAddressSync(s, programId)[0];
  const t = (s: string) => new TextEncoder().encode(s);
  return {
    config: p(t("config")),
    tree: p(t("tree")),
    vault: p(t("vault")),
    treasuryVault: p(t("treasury_vault")),
    burnVault: p(t("burn_vault")),
    member: (commitment: bigint) => p(t("member"), fieldToBytes(commitment)),
    tokenPay: p(t("token_pay")),
    order: (key: PublicKey) => p(t("order"), key.toBytes()),
    orderVault: (key: PublicKey) => p(t("order_vault"), key.toBytes()),
    stake: p(t("stake")),
    stakeVault: p(t("stake_vault")),
    stakePosition: (member: PublicKey) => p(t("stake_position"), member.toBytes()),
    walletStake: (owner: PublicKey) => p(t("wallet_stake"), owner.toBytes()),
    stakeReward: p(t("stake_reward")),
    stakeRewardVault: p(t("stake_reward_vault")),
  };
}

export function ata(owner: PublicKey, mint = USDC_MINT): PublicKey {
  return PublicKey.findProgramAddressSync([owner.toBytes(), TOKEN_PROGRAM.toBytes(), mint.toBytes()], ATA_PROGRAM)[0];
}

const view = (d: Uint8Array) => new DataView(d.buffer, d.byteOffset, d.byteLength);
const toHexStr = (d: Uint8Array) => Array.from(d, (x) => x.toString(16).padStart(2, "0")).join("");

/** v2 (question packs): `rate` is the price of one question, `limit` the most tickets one membership
 *  may hold, `maxEpochs` the days a purchase stays valid, `minQuestions` the smallest purchase. */
export type Config = {
  treasury: PublicKey; genesis: number; epochSeconds: number; rate: bigint; limit: number; maxEpochs: number;
  minQuestions: number; burnBps: number; slashBurnBps: number; members: bigint; deposited: bigint;
  paidTreasury: bigint; paidBurn: bigint; refunded: bigint; tokenBurned: bigint;
};

export function decodeConfig(d: Uint8Array): Config {
  if (toHexStr(d.subarray(0, 8)) !== DISC.config) throw new Error("not a PARANOID config account");
  const v = view(d);
  return {
    treasury: new PublicKey(d.subarray(9, 41)),
    genesis: Number(v.getBigInt64(41, true)),
    epochSeconds: v.getUint32(49, true),
    rate: v.getBigUint64(53, true),
    limit: v.getUint16(61, true),
    maxEpochs: v.getUint32(63, true),
    minQuestions: v.getUint32(67, true),
    burnBps: v.getUint16(71, true),
    slashBurnBps: v.getUint16(73, true),
    members: v.getBigUint64(139, true),
    deposited: v.getBigUint64(147, true),
    paidTreasury: v.getBigUint64(155, true),
    paidBurn: v.getBigUint64(163, true),
    refunded: v.getBigUint64(171, true),
    tokenBurned: v.getBigUint64(195, true),
  };
}

export const STATUS = ["active", "slashed"] as const;
/** Member (v2): disc 8 | bump 1 | depositor 32 | commitment 32 | leaf_index u32 | start_epoch u32 | end_epoch u32 | questions u64 | status u8. */
export type Member = {
  address: PublicKey; depositor: PublicKey; commitment: bigint; leafIndex: number; startEpoch: number; endEpoch: number;
  questions: number; status: (typeof STATUS)[number];
};
export const MEMBER_SIZE = 94;

export function decodeMember(address: PublicKey, d: Uint8Array): Member {
  const v = view(d);
  return {
    address,
    depositor: new PublicKey(d.subarray(9, 41)),
    commitment: bytesToField(d.subarray(41, 73)),
    leafIndex: v.getUint32(73, true),
    startEpoch: v.getUint32(77, true),
    endEpoch: v.getUint32(81, true),
    questions: Number(v.getBigUint64(85, true)),
    status: STATUS[d[93]],
  };
}

/** Tree account (zero copy): disc 8 | next_index u32 | head u32 | zeros 21*32 | filled 20*32 | roots 64*(root 32 | valid_before u32). */
export function decodeRoots(d: Uint8Array): { root: bigint; validBefore: number }[] {
  const v = view(d);
  const out = [];
  for (let i = 0; i < 64; i++) {
    const o = 16 + 21 * 32 + 20 * 32 + i * 36;
    const root = bytesToField(d.subarray(o, o + 32));
    const validBefore = v.getUint32(o + 32, true);
    if (validBefore !== 0) out.push({ root, validBefore });
  }
  return out;
}

export function epochAt(cfg: Config, unixSeconds: number): number {
  return Math.max(0, Math.floor((unixSeconds - cfg.genesis) / cfg.epochSeconds));
}

/** Chain time, not the computer's clock: a local validator can drift from wall time. */
export async function chainNow(conn: Connection): Promise<number> {
  const slot = await conn.getSlot("confirmed");
  // The newest block's time is sometimes not served yet ("Block not available"); the ones just
  // before it are, and are under a second older.
  for (let s = slot; s > slot - 3; s--) {
    const t = await conn.getBlockTime(s).catch(() => undefined);
    if (t !== undefined) return t ?? Math.floor(Date.now() / 1000);
  }
  return Math.floor(Date.now() / 1000);
}

export async function readConfig(conn: Connection, programId: PublicKey): Promise<Config | null> {
  const a = await conn.getAccountInfo(pdas(programId).config, "confirmed");
  return a ? decodeConfig(a.data) : null;
}

export async function readMembers(conn: Connection, programId: PublicKey): Promise<Member[]> {
  const all = await conn.getProgramAccounts(programId, { commitment: "confirmed", filters: [{ dataSize: MEMBER_SIZE }] });
  return all.map(({ pubkey, account }: { pubkey: PublicKey; account: AccountInfo<Buffer> }) => decodeMember(pubkey, account.data));
}

/** The tree exactly as the program holds it: a leaf for every active member, nothing for the rest. */
export function treeOf(members: Member[]): Tree {
  return buildTree(new Map(members.filter((m) => m.status === "active").map((m) => [m.leafIndex, leafOf(m.commitment, m.endEpoch, m.questions)])));
}

export const siblingsOf = (tree: Tree, leafIndex: number) => tree.path(leafIndex).pathElements.map(fieldToBytes);

function vecOf32(items: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(4 + 32 * items.length);
  view(out).setUint32(0, items.length, true);
  items.forEach((x, i) => out.set(x, 4 + 32 * i));
  return out;
}
const cat = (...a: Uint8Array[]) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const w = (pubkey: PublicKey) => ({ pubkey, isSigner: false, isWritable: true });
const r = (pubkey: PublicKey) => ({ pubkey, isSigner: false, isWritable: false });

const u32le = (n: number) => { const e = new Uint8Array(4); view(e).setUint32(0, n, true); return e; };

// ---- paying with the PARANOID token (engine/programs/paranoid/src/meteora.rs, instructions/token_pay.rs)

export const PARANOID_MINT = new PublicKey("22rWiyDiY9GgxSrFiWC2vX1GxNxjkvrRPmZJDzv9pq6X");
const TOKEN_PAY_DISCRIMINATOR = "80e125d02d705b1c";

export interface TokenPay { mint: PublicKey; pool: PublicKey; priceUpdate: PublicKey; premiumBps: number; questionsSold: bigint; tokensBurned: bigint }

export function decodeTokenPay(d: Uint8Array): TokenPay | null {
  if (d.length < 8 + 1 + 32 * 3 + 2 + 16 || Buffer.from(d.subarray(0, 8)).toString("hex") !== TOKEN_PAY_DISCRIMINATOR) return null;
  const v = view(d);
  return {
    mint: new PublicKey(d.subarray(9, 41)),
    pool: new PublicKey(d.subarray(41, 73)),
    priceUpdate: new PublicKey(d.subarray(73, 105)),
    premiumBps: v.getInt16(105, true),
    questionsSold: v.getBigUint64(107, true),
    tokensBurned: v.getBigUint64(115, true),
  };
}

/** PARANOID base units the program will burn for `usdc` base units of questions: the same math as
 *  `token_cost` in meteora.rs, from the same pool and Pyth bytes. */
export function tokenQuote(usdc: bigint, premiumBps: number, pool: Uint8Array, pyth: Uint8Array, mint: PublicKey): bigint {
  const pv = view(pool), yv = view(pyth);
  const sqrt = pv.getBigUint64(456, true) + (pv.getBigUint64(464, true) << 64n);
  const paranoidIsA = new PublicKey(pool.subarray(168, 200)).equals(mint);
  const price = yv.getBigInt64(41 + 32, true);
  const expo = yv.getInt32(41 + 48, true);
  const ceil = (a: bigint, b: bigint) => (a + b - 1n) / b;
  const q64 = 1n << 64n;
  const n = usdc * (10_000n + BigInt(premiumBps)) * 1_000n * 10n ** BigInt(-expo);
  const t = paranoidIsA ? ceil(ceil(n * q64, sqrt) * q64, sqrt) : ceil(ceil(n * sqrt, q64) * sqrt, q64);
  return ceil(t, price * 10_000n);
}

/** USD per PARANOID from the same accounts, for showing a dollar figure next to a token amount. */
export function tokenUsd(pool: Uint8Array, pyth: Uint8Array, mint: PublicKey): number {
  const pv = view(pool), yv = view(pyth);
  const sqrt = Number(pv.getBigUint64(456, true) + (pv.getBigUint64(464, true) << 64n)) / 2 ** 64;
  const paranoidIsA = new PublicKey(pool.subarray(168, 200)).equals(mint);
  const solUsd = Number(yv.getBigInt64(41 + 32, true)) * 10 ** yv.getInt32(41 + 48, true);
  const solPer = paranoidIsA ? sqrt * sqrt : 1 / (sqrt * sqrt);
  return solPer * solUsd;
}

const u64le = (n: bigint) => { const e = new Uint8Array(8); view(e).setBigUint64(0, n, true); return e; };

/** A new membership paid in PARANOID: burns at most `maxTokens` from the depositor's token account. */
export function ixDepositToken(programId: PublicKey, depositor: PublicKey, commitment: bigint, questions: number, maxTokens: bigint, tp: TokenPay): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: depositor, isSigner: true, isWritable: true }, w(k.config), w(k.tree), w(k.member(commitment)), w(k.tokenPay), w(tp.mint), w(ata(depositor, tp.mint)), r(tp.pool), r(tp.priceUpdate), r(TOKEN_PROGRAM), r(SystemProgram.programId)],
    data: Buffer.from(cat(IX.deposit_token, fieldToBytes(commitment), u32le(questions), u64le(maxTokens))),
  });
}

/** More tickets for the same membership, paid in PARANOID. */
export function ixTopUpToken(programId: PublicKey, depositor: PublicKey, m: Member, tree: Tree, questions: number, maxTokens: bigint, tp: TokenPay): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: depositor, isSigner: true, isWritable: true }, r(k.config), w(k.tree), w(m.address), w(k.tokenPay), w(tp.mint), w(ata(depositor, tp.mint)), r(tp.pool), r(tp.priceUpdate), r(TOKEN_PROGRAM)],
    data: Buffer.from(cat(IX.top_up_token, u32le(questions), vecOf32(siblingsOf(tree, m.leafIndex)), u64le(maxTokens))),
  });
}

/** Buys `questions` tickets for a new membership; the money goes straight to the treasury and burn vaults. */
export function ixDeposit(programId: PublicKey, depositor: PublicKey, commitment: bigint, questions: number): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: depositor, isSigner: true, isWritable: true }, w(k.config), w(k.tree), w(k.member(commitment)), w(ata(depositor)), w(k.treasuryVault), w(k.burnVault), r(TOKEN_PROGRAM), r(SystemProgram.programId)],
    data: Buffer.from(cat(IX.deposit, fieldToBytes(commitment), u32le(questions))),
  });
}

/** Pays `amount` USDC into a gift card order's vault for the throwaway `key`. One instruction, like buying questions. */
export function ixOpenOrder(programId: PublicKey, buyer: PublicKey, key: PublicKey, amount: bigint): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: buyer, isSigner: true, isWritable: true }, r(key), w(k.order(key)), w(k.orderVault(key)), w(ata(buyer)), r(USDC_MINT), r(TOKEN_PROGRAM), r(SystemProgram.programId)],
    data: Buffer.from(cat(IX.open_order, u64le(amount))),
  });
}

/** Empties an order into `destination` and closes it, deposits back to the buyer. Signed by the key,
 *  or by the buyer sending it back to themselves. */
export function ixSettleOrder(programId: PublicKey, signer: PublicKey, key: PublicKey, buyer: PublicKey, destination: PublicKey): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: signer, isSigner: true, isWritable: false }, w(k.order(key)), w(buyer), w(k.orderVault(key)), w(destination), r(TOKEN_PROGRAM)],
    data: Buffer.from(cat(IX.settle_order)),
  });
}

/** Buys `questions` more tickets for the same membership and renews it for a full year. */
export function ixTopUp(programId: PublicKey, depositor: PublicKey, m: Member, tree: Tree, questions: number): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: depositor, isSigner: true, isWritable: true }, w(k.config), w(k.tree), w(m.address), w(ata(depositor)), w(k.treasuryVault), w(k.burnVault), r(TOKEN_PROGRAM)],
    data: Buffer.from(cat(IX.top_up, u32le(questions), vecOf32(siblingsOf(tree, m.leafIndex)))),
  });
}

export function ixSlash(programId: PublicKey, cfg: Config, reporter: PublicKey, m: Member, tree: Tree, secret: bigint) {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: reporter, isSigner: true, isWritable: false }, r(k.config), w(k.tree), w(m.address)],
    data: Buffer.from(cat(IX.slash, fieldToBytes(secret), vecOf32(siblingsOf(tree, m.leafIndex)))),
  });
}

// ---- stake: $PARANOID held in the program shares every buyback ----

/** A wallet's stake. `unstakeAt` is 0 while staked; after asking to unstake, the unix time the tokens
 *  can be taken back. `perTokenSeen` is the share already counted into `tokensOwed` (bought tokens not yet claimed). */
export interface WalletStake { address: PublicKey; owner: PublicKey; amount: bigint; unstakeAt: number; perTokenSeen: bigint; tokensOwed: bigint }
const WALLET_STAKE_DISC = "5e0b1c6552d1831b";
const u128 = (v: DataView, at: number) => v.getBigUint64(at, true) + (v.getBigUint64(at + 8, true) << 64n);
export function decodeWalletStake(address: PublicKey, d: Uint8Array): WalletStake | null {
  if (d.length < 81 || toHexStr(d.subarray(0, 8)) !== WALLET_STAKE_DISC) return null;
  const v = view(d);
  return {
    address, owner: new PublicKey(d.subarray(9, 41)), amount: v.getBigUint64(41, true), unstakeAt: Number(v.getBigInt64(49, true)),
    perTokenSeen: u128(v, 57), tokensOwed: v.getBigUint64(73, true),
  };
}

/** A stake from before 2026-10-27, which sat on a membership; it can only be returned. */
export interface LegacyStake { address: PublicKey; member: PublicKey; amount: bigint }
const STAKE_POSITION_DISC = "4ea51e6fab7d0bdc";
export function decodeLegacyStake(address: PublicKey, d: Uint8Array): LegacyStake | null {
  if (d.length < 81 || toHexStr(d.subarray(0, 8)) !== STAKE_POSITION_DISC) return null;
  return { address, member: new PublicKey(d.subarray(9, 41)), amount: view(d).getBigUint64(41, true) };
}

/** The $PARANOID the buyback handed to stakers. */
export interface StakeReward { perToken: bigint; earning: bigint; given: bigint; claimed: bigint }
export function decodeStakeReward(d: Uint8Array): StakeReward {
  const v = view(d);
  return { perToken: u128(v, 9), earning: v.getBigUint64(25, true), given: v.getBigUint64(33, true), claimed: v.getBigUint64(41, true) };
}
const REWARD_SCALE = 1_000_000_000_000n;
/** Bought tokens (base units) a stake can claim now, as the program will count them. */
export function stakeTokens(p: WalletStake, r: StakeReward): bigint {
  return p.tokensOwed + (p.unstakeAt ? 0n : (p.amount * (r.perToken - p.perTokenSeen)) / REWARD_SCALE);
}

/** Opens the wallet's stake with `amount` tokens. */
export function ixStartStake(programId: PublicKey, owner: PublicKey, amount: bigint): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: owner, isSigner: true, isWritable: true }, w(k.walletStake(owner)), w(ata(owner, PARANOID_MINT)),
      w(k.stake), w(k.stakeVault), w(k.stakeReward), r(TOKEN_PROGRAM), r(SystemProgram.programId)],
    data: Buffer.from(cat(IX.start_stake, u64le(amount))),
  });
}

/** Adds tokens to the wallet's stake. */
export function ixAddStake(programId: PublicKey, owner: PublicKey, amount: bigint): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: owner, isSigner: true, isWritable: false }, w(k.walletStake(owner)), w(ata(owner, PARANOID_MINT)),
      w(k.stake), w(k.stakeVault), w(k.stakeReward), r(TOKEN_PROGRAM)],
    data: Buffer.from(cat(IX.add_stake, u64le(amount))),
  });
}

/** Stops the stake earning and starts the 3-day wait before the tokens can be taken back. */
export function ixRequestUnstake(programId: PublicKey, owner: PublicKey): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: owner, isSigner: true, isWritable: false }, r(k.config), w(k.walletStake(owner)), w(k.stakeReward)],
    data: Buffer.from(cat(IX.request_unstake)),
  });
}

/** 3 days after asking to unstake: every staked token, and the bought tokens not yet claimed, back to the wallet. */
export function ixWithdrawStake(programId: PublicKey, owner: PublicKey): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: owner, isSigner: true, isWritable: true }, w(k.walletStake(owner)), w(ata(owner, PARANOID_MINT)),
      w(k.stake), w(k.stakeVault), w(k.stakeReward), w(k.stakeRewardVault), r(TOKEN_PROGRAM)],
    data: Buffer.from(cat(IX.withdraw_stake)),
  });
}

/** Sends the bought $PARANOID the stake has earned to the wallet. */
export function ixClaimStakeReward(programId: PublicKey, owner: PublicKey): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: owner, isSigner: true, isWritable: false }, w(k.walletStake(owner)), w(ata(owner, PARANOID_MINT)),
      r(k.stake), w(k.stakeReward), w(k.stakeRewardVault), r(TOKEN_PROGRAM)],
    data: Buffer.from(cat(IX.claim_stake_reward)),
  });
}

/** Returns a stake from before 2026-10-27 to the wallet that paid its membership, at once. */
export function ixReturnLegacyStake(programId: PublicKey, depositor: PublicKey, m: Member): TransactionInstruction {
  const k = pdas(programId);
  return new TransactionInstruction({
    programId,
    keys: [{ pubkey: depositor, isSigner: true, isWritable: true }, r(m.address), w(k.stakePosition(m.address)), w(ata(depositor, PARANOID_MINT)),
      w(k.stake), w(k.stakeVault), r(TOKEN_PROGRAM)],
    data: Buffer.from(cat(IX.return_legacy_stake)),
  });
}

/** Program errors in words a member understands (codes 6000 + position in error.rs). */
export const PLAIN_ERRORS: Record<number, string> = {
  6004: "That member secret is not valid. Make a new one.",
  6006: "The member list is full.",
  6007: "The member list changed while you were signing. Try again.",
  6009: "Only the wallet that paid can do this.",
  6010: "This membership is not active.",
  6012: "This membership was slashed for spending one ticket twice.",
  6013: "That secret does not belong to this member.",
  6018: "Buy at least the minimum number of questions, and stay under the most one membership can hold.",
  6020: "Paying with $PARANOID is not set up yet.",
  6021: "The SOL price feed did not answer properly. Try again in a moment.",
  6022: "The SOL price is more than a minute old. Try again in a moment.",
  6023: "The $PARANOID price moved past your quote. Check the new amount and try again.",
  6027: "Enter how much $PARANOID to stake.",
  6029: "This stake is already being unstaked.",
  6030: "Your tokens come back 3 days after you ask to unstake.",
  6031: "Your stake has not earned any $PARANOID to claim yet.",
};

export function plainError(e: unknown): string {
  const s = String((e as { message?: string })?.message ?? e);
  const m = s.match(/custom program error: 0x([0-9a-f]+)/i) ?? s.match(/"Custom":(\d+)/);
  if (m) {
    const code = m[0].includes("0x") ? parseInt(m[1], 16) : Number(m[1]);
    if (PLAIN_ERRORS[code]) return PLAIN_ERRORS[code];
  }
  if (/insufficient funds|0x1\b/i.test(s)) return "Your wallet does not hold enough USDC for this.";
  if (/rejected/i.test(s)) return "You declined the request in your wallet.";
  return s.length > 200 ? s.slice(0, 200) + "..." : s;
}
