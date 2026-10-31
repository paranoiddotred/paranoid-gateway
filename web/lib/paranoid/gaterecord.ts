// The list of gateway builds the browser accepts, kept on Solana instead of in the site's code.
// It lives in one account of the SPL Record program (recr1L3P..., the shared program for raw records): 33 bytes
// of header (version, authority), then our bytes. The authority is PARANOID's 2-of-3 Squads vault, so the list
// changes only through a multisig vote, and every change is a public Solana transaction.
//
// Our bytes: "PGW1", a count (at most MAX), then per build a 16-byte tag (ASCII, zero padded) and its
// measurements: the compose hash (32 bytes), MRTD, RTMR0, RTMR1 and RTMR2 (48 bytes each).
import { PublicKey, TransactionInstruction } from "@solana/web3.js";

export const RECORD_PROGRAM = new PublicKey("recr1L3PCGKLbckBqMNcJhuuyU1zgo8nBhfLVsJNwr5");
export const HEADER = 33;
export const MAX = 2; // the build in use, and the next one while a new box rolls out
const MAGIC = "PGW1";
const ENTRY = 16 + 32 + 48 * 4;
export const SIZE = HEADER + MAGIC.length + 1 + MAX * ENTRY;

export type Build = { tag: string; compose: string; mrtd: string; rtmr0: string; rtmr1: string; rtmr2: string };

const hex = (u: Uint8Array) => Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");
function unhex(h: string, len: number): Uint8Array {
  const u = Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
  if (u.length !== len || hex(u) !== h.toLowerCase()) throw new Error(`expected ${len} bytes of hex`);
  return u;
}

/** Our bytes for a list of builds (what goes after the header). */
export function encodeBuilds(builds: Build[]): Uint8Array {
  if (builds.length < 1 || builds.length > MAX) throw new Error(`between 1 and ${MAX} builds`);
  const out = new Uint8Array(SIZE - HEADER);
  out.set(new TextEncoder().encode(MAGIC), 0);
  out[4] = builds.length;
  builds.forEach((b, i) => {
    const tag = new TextEncoder().encode(b.tag);
    if (tag.length < 1 || tag.length > 16) throw new Error("tag must be 1 to 16 ASCII bytes");
    let o = 5 + i * ENTRY;
    out.set(tag, o); o += 16;
    out.set(unhex(b.compose, 32), o); o += 32;
    for (const m of [b.mrtd, b.rtmr0, b.rtmr1, b.rtmr2]) { out.set(unhex(m, 48), o); o += 48; }
  });
  return out;
}

/** The builds in a record account, after checking it is ours: owned by the Record program, version 1,
 *  written by `authority`, and in our format. Throws on anything else. */
export function decodeRecord(owner: PublicKey, data: Uint8Array, authority: PublicKey): Build[] {
  if (!owner.equals(RECORD_PROGRAM)) throw new Error("not a record account");
  if (data.length < SIZE || data[0] !== 1) throw new Error("not a version 1 record of our size");
  if (!new PublicKey(data.slice(1, HEADER)).equals(authority)) throw new Error("the record is not written by PARANOID's multisig");
  const body = data.slice(HEADER);
  if (new TextDecoder().decode(body.slice(0, 4)) !== MAGIC) throw new Error("the record holds no gateway list");
  const n = body[4];
  if (n < 1 || n > MAX) throw new Error("the gateway list is empty");
  return Array.from({ length: n }, (_, i) => {
    let o = 5 + i * ENTRY;
    const tag = new TextDecoder().decode(body.slice(o, o + 16)).replace(/\0+$/, ""); o += 16;
    const compose = hex(body.slice(o, o + 32)); o += 32;
    const [mrtd, rtmr0, rtmr1, rtmr2] = [0, 1, 2, 3].map((k) => hex(body.slice(o + k * 48, o + (k + 1) * 48)));
    return { tag, compose, mrtd, rtmr0, rtmr1, rtmr2 };
  });
}

/** Record program Initialize: the account must already exist, owned by the Record program, SIZE bytes. */
export const ixInitialize = (record: PublicKey, authority: PublicKey) =>
  new TransactionInstruction({ programId: RECORD_PROGRAM, keys: [{ pubkey: record, isSigner: false, isWritable: true }, { pubkey: authority, isSigner: false, isWritable: false }], data: Buffer.from([0]) });

/** Record program Write of the whole list, signed by the authority. */
export function ixWriteBuilds(record: PublicKey, authority: PublicKey, builds: Build[]) {
  const bytes = encodeBuilds(builds);
  const data = Buffer.alloc(1 + 8 + 4 + bytes.length);
  data[0] = 1; data.writeBigUInt64LE(0n, 1); data.writeUInt32LE(bytes.length, 9); data.set(bytes, 13);
  return new TransactionInstruction({ programId: RECORD_PROGRAM, keys: [{ pubkey: record, isSigner: false, isWritable: true }, { pubkey: authority, isSigner: true, isWritable: false }], data });
}
