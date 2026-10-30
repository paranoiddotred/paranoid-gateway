// Server-side settings for the gateway and the RPC relay, read from the environment once.
// Defaults are the local test setup (product/scripts/localnet.sh); production sets every one.
import { Keypair, PublicKey } from "@solana/web3.js";
import vkey from "./verification_key.json" with { type: "json" };
import type { GatewayEnv } from "./gateway.ts";

export const PROGRAM_ID = new PublicKey(process.env.NEXT_PUBLIC_PARANOID_PROGRAM ?? "9JJqzEoDGkTE8CMLATRw7CqFhcyWVegfhFuEeGfBfVGm");
export const RPC = process.env.PARANOID_RPC ?? "http://127.0.0.1:48899";
/** `cost` is how many questions one message to this model spends; `maxTokens` caps its answer;
 *  `maxInput` caps the characters of the conversation sent to it (older messages are left out first),
 *  so a long chat cannot cost more than its price; `body` holds fields always sent to it, such as
 *  thinking switched off; `images` says a model off Chutes can read photos (Chutes models say so
 *  themselves, lib/paranoid/chips.ts). */
export type Model = { url: string; name: string; key: string; label: string; cost: number; maxTokens?: number; maxInput?: number; body?: Record<string, unknown>; images?: boolean };
export const MODEL: Model = {
  url: process.env.PARANOID_MODEL_URL ?? "http://127.0.0.1:41535/v1",
  name: process.env.PARANOID_MODEL_NAME ?? "qwen2.5:7b",
  key: process.env.PARANOID_MODEL_KEY ?? "",
  label: "Smart",
  cost: 1,
  images: process.env.PARANOID_MODEL_IMAGES === "1",
};
/** More models, each on its own box, from PARANOID_EXTRA_MODELS: a JSON list of {url, name, label, key?, keyEnv?, cost?, maxTokens?, body?, images?}.
 *  PARANOID_FAST_URL/NAME is the older spelling of one extra. Without its own key a model uses the model password.
 *  `keyEnv` names the setting that holds the key instead, so the list (where questions go) can stay in plain view
 *  while only the key is secret. */
const FAST: Model | null = process.env.PARANOID_FAST_URL
  ? { url: process.env.PARANOID_FAST_URL, name: process.env.PARANOID_FAST_NAME ?? "qwen3-30b", key: MODEL.key, label: "Fast", cost: 1 }
  : null;
const EXTRA: Model[] = (JSON.parse(process.env.PARANOID_EXTRA_MODELS ?? "[]") as (Omit<Model, "key" | "cost"> & { key?: string; keyEnv?: string; cost?: number })[])
  .map(({ keyEnv, ...m }) => ({ ...m, key: m.key ?? (keyEnv ? process.env[keyEnv] ?? "" : MODEL.key), cost: Math.max(1, Math.floor(m.cost ?? 1)) }));
export const MODELS: Model[] = [MODEL, ...(FAST ? [FAST] : []), ...EXTRA]
  .filter((m, i, all) => all.findIndex((o) => o.name === m.name) === i);
/** The model a request names, or the default for any other name ("gpt-4o", "any"), so every app keeps working. */
export const pickModel = (asked: unknown): Model => MODELS.find((m) => m.name === asked) ?? MODEL;
const reporter = process.env.PARANOID_REPORTER_KEY ? Keypair.fromSecretKey(Uint8Array.from(JSON.parse(process.env.PARANOID_REPORTER_KEY))) : undefined;
export const GATEWAY: GatewayEnv = { rpc: RPC, programId: PROGRAM_ID, vkey, reporter };
