// The site's fingerprint on Solana: the SHA-256 of the list web/scripts/site-manifest.mjs writes after each
// build, kept in one SPL Record account whose authority is PARANOID's 2-of-3 Squads vault (the same setup as
// the gateway list, gaterecord.ts). The PARANOID Chrome extension reads it straight from Solana and checks
// every paranoid.red page against the list, so the site cannot serve code the multisig did not record.
//
// Our bytes after the 33-byte record header: "PSW1", a count (1 or 2: the site in use, and the next one while
// a deploy rolls out), then one 32-byte manifest hash per site. extension/sitecheck.js decodes the same bytes.
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { RECORD_PROGRAM, HEADER } from "./gaterecord.ts";

export const MAX = 2;
const MAGIC = "PSW1";
export const SIZE = HEADER + MAGIC.length + 1 + MAX * 32;

const hex = (u: Uint8Array) => Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");

/** Our bytes for one or two manifest hashes (64 hex characters each). */
export function encodeSites(hashes: string[]): Uint8Array {
  if (hashes.length < 1 || hashes.length > MAX) throw new Error(`between 1 and ${MAX} site hashes`);
  const out = new Uint8Array(SIZE - HEADER);
  out.set(new TextEncoder().encode(MAGIC), 0);
  out[4] = hashes.length;
  hashes.forEach((h, i) => {
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error("a site hash is 64 lowercase hex characters");
    out.set(Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16)), 5 + i * 32);
  });
  return out;
}

/** The manifest hashes in a record account, after checking it is ours. Throws on anything else. */
export function decodeSites(owner: PublicKey, data: Uint8Array, authority: PublicKey): string[] {
  if (!owner.equals(RECORD_PROGRAM)) throw new Error("not a record account");
  if (data.length < SIZE || data[0] !== 1) throw new Error("not a version 1 record of our size");
  if (!new PublicKey(data.slice(1, HEADER)).equals(authority)) throw new Error("the record is not written by PARANOID's multisig");
  const body = data.slice(HEADER);
  if (new TextDecoder().decode(body.slice(0, 4)) !== MAGIC) throw new Error("the record holds no site fingerprint");
  const n = body[4];
  if (n < 1 || n > MAX) throw new Error("the site record is empty");
  return Array.from({ length: n }, (_, i) => hex(body.slice(5 + i * 32, 5 + (i + 1) * 32)));
}

/** Record program Write of the whole list, signed by the authority. */
export function ixWriteSites(record: PublicKey, authority: PublicKey, hashes: string[]) {
  const bytes = encodeSites(hashes);
  const data = Buffer.alloc(1 + 8 + 4 + bytes.length);
  data[0] = 1; data.writeBigUInt64LE(0n, 1); data.writeUInt32LE(bytes.length, 9); data.set(bytes, 13);
  return new TransactionInstruction({ programId: RECORD_PROGRAM, keys: [{ pubkey: record, isSigner: false, isWritable: true }, { pubkey: authority, isSigner: true, isWritable: false }], data });
}
