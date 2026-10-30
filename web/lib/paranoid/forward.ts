// Forward one OpenAI-style chat request to the model, carrying nothing that could identify the sender.
// The gateway builds a brand-new request: only the fields below cross over. No client headers,
// no `user` field, no IP, no cookies. Nothing is written anywhere.

const PASS_FIELDS = ["model", "messages", "max_tokens", "max_completion_tokens", "temperature", "top_p", "stop", "stream", "presence_penalty", "frequency_penalty", "seed", "response_format", "reasoning_effort"] as const;

/** Longest answer one request may ask for, so one member cannot hold the shared model for long. */
export const MAX_OUTPUT_TOKENS = 8192;
/** The model thinks before it answers; below this, apps asking for a few tokens would get an empty answer. */
export const MIN_OUTPUT_TOKENS = 1024;

/** `fixed` is the model's own settings (such as thinking switched off); they win over the caller's. */
export function cleanBody(body: Record<string, unknown>, model: string, cap = MAX_OUTPUT_TOKENS, fixed: Record<string, unknown> = {}): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of PASS_FIELDS) if (body[k] !== undefined) out[k] = body[k];
  out.model = model;
  const asked = Number(out.max_completion_tokens ?? out.max_tokens);
  delete out.max_completion_tokens;
  // A thinking model spends tokens before the answer; too small a budget would end mid-thought with no answer.
  const min = /r1|deepseek|thinking|gpt-5|gemini-3|grok-4/i.test(model) ? 4096 : MIN_OUTPUT_TOKENS;
  const limit = asked > 0 ? Math.min(Math.max(asked, min), cap) : cap;
  // OpenAI's GPT-5 models take the newer field and refuse the old one.
  if (/^openai\/gpt-5/i.test(model)) { delete out.max_tokens; out.max_completion_tokens = limit; }
  else out.max_tokens = limit;
  // gpt-oss thinks before it answers; keep that short by default. Models without a thinking step reject the field.
  if (/gpt-oss/i.test(model)) out.reasoning_effort ??= "low";
  return { ...out, ...fixed };
}

const chars = (content: unknown): number =>
  typeof content === "string" ? content.length
    : Array.isArray(content) ? content.reduce((n: number, p: { text?: unknown }) => n + (typeof p?.text === "string" ? p.text.length : 0), 0) : 0;

/** The conversation cut to at most `max` characters: system messages stay, then the newest messages that
 *  fit, so the oldest turns are left out first. Null when the newest message alone is too long. */
export function fitMessages(messages: { role?: unknown; content?: unknown }[], max: number): { role?: unknown; content?: unknown }[] | null {
  const system = messages.filter((m) => m.role === "system");
  const rest = messages.filter((m) => m.role !== "system");
  let left = max - system.reduce((n, m) => n + chars(m.content), 0);
  const kept: typeof messages = [];
  for (let i = rest.length - 1; i >= 0; i--) {
    const n = chars(rest[i].content);
    if (n > left) break;
    kept.unshift(rest[i]);
    left -= n;
  }
  if (rest.length && kept.length === 0) return null;
  return [...system, ...kept];
}

/** Calls the upstream model. `upstream` is an OpenAI-compatible base URL such as http://127.0.0.1:41535/v1. */
export async function forwardChat(upstream: string, apiKey: string, body: Record<string, unknown>): Promise<Response> {
  const res = await fetch(`${upstream.replace(/\/$/, "")}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}) },
    body: JSON.stringify(body),
  });
  // Pass the body through untouched (works for both JSON and server-sent events), but only our own headers.
  return new Response(res.body, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json", "cache-control": "no-store" },
  });
}
