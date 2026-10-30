// The public list of spent tickets, one hex nullifier per line. A member's browser downloads it and
// looks for its own nullifiers locally, so a new device learns how many questions are used without
// telling anyone which ones are its own.
import { usedNullifiers } from "@/lib/paranoid/gateway";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function GET() {
  return new Response(usedNullifiers().map((n) => n.toString(16)).join("\n"), {
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
