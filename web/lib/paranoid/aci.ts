// The gateway's side of sealing questions to an ACI gateway (Attested Confidential Inference, as RedPill
// runs at tee.redpill.ai). The browser checks the gateway's TDX proof and encrypts each message to a key
// that proof names (E2EE v2, app/app/aci.ts); this side only fetches the proof with our account key and
// passes the encrypted request along, so it never holds a key that opens the question or the answer.
import type { Model } from "./server.ts";
import { collateralFor } from "./chips.ts";

const ACI_HOSTS = new Set(["tee.redpill.ai"]);

/** Whether the model sits behind an ACI gateway that takes questions sealed in the browser. */
export const isAci = (model: Model) => ACI_HOSTS.has(new URL(model.url).host);

/** The gateway's attestation report for the browser's nonce, and Intel's signed collateral for its quote. */
export async function aciReport(model: Model, nonce: string) {
  const r = await fetch(`${model.url.replace(/\/$/, "")}/aci/attestation?nonce=${nonce}`, { headers: { authorization: `Bearer ${model.key}` }, signal: AbortSignal.timeout(20_000) });
  if (!r.ok) throw new Error(`attestation ${r.status}`);
  const report = (await r.json()) as { attestation?: { evidence?: { quote?: string } } };
  const quote = report.attestation?.evidence?.quote;
  if (!quote || !/^[0-9a-f]+$/i.test(quote)) throw new Error("no quote");
  return { report, collateral: await collateralFor(Uint8Array.from(Buffer.from(quote, "hex"))) };
}

/** The five E2EE v2 headers the browser sets; only these cross over, next to our account key. */
export const E2EE_HEADERS = ["x-e2ee-version", "x-client-pub-key", "x-model-pub-key", "x-e2ee-nonce", "x-e2ee-timestamp"] as const;

/** Sends the browser's encrypted request with our account key and streams the encrypted answer back. */
export async function forwardAci(model: Model, body: Record<string, unknown>, e2ee: Record<string, string>, signal?: AbortSignal): Promise<Response> {
  const res = await fetch(`${model.url.replace(/\/$/, "")}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${model.key}`, ...e2ee },
    body: JSON.stringify(body),
    signal,
  });
  const headers = new Headers({ "content-type": res.headers.get("content-type") ?? "application/json", "cache-control": "no-store" });
  for (const h of ["x-e2ee-applied", "x-e2ee-algo"]) { const v = res.headers.get(h); if (v) headers.set(h, v); }
  return new Response(res.body, { status: res.status, headers });
}
