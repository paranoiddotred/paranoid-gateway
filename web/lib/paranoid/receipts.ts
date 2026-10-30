// One-use search receipts. A sealed call that asked the chip for search words gets one, and the
// search must hand it back, so every web search is paid for by that call's ticket. A receipt is
// random, says nothing about who holds it, and lives three minutes in memory.
import { randomBytes } from "node:crypto";

const TTL = 3 * 60_000;
const g = globalThis as unknown as { __receipts?: Map<string, number> };
const book = (g.__receipts ??= new Map());

export function issueReceipt(): string {
  const now = Date.now();
  for (const [r, until] of book) if (until < now) book.delete(r);
  const r = randomBytes(16).toString("hex");
  book.set(r, now + TTL);
  return r;
}

export function takeReceipt(r: string): boolean {
  const until = book.get(r);
  if (until === undefined) return false;
  book.delete(r);
  return until >= Date.now();
}
