// Talking to the chip: inside a dstack confidential VM, /var/run/dstack.sock derives keys only this app can
// get and signs quotes that name what we put in them. DSTACK_SIMULATOR_ENDPOINT points at a stand-in for
// local tests. Outside both, the gateway runs as before and has no proof to give.
import { existsSync } from "node:fs";
import { request } from "node:http";
import { createHash } from "node:crypto";

const SOCKET = "/var/run/dstack.sock";
const SIM = process.env.DSTACK_SIMULATOR_ENDPOINT?.replace(/\/$/, "");
export const inTee = (): boolean => !!SIM || existsSync(SOCKET);

function call<T>(path: string, body: unknown): Promise<T> {
  const data = JSON.stringify(body);
  const target = SIM ? new URL(SIM + path) : null;
  return new Promise((resolve, reject) => {
    const req = request({
      ...(target ? { host: target.hostname, port: target.port, path: target.pathname } : { socketPath: SOCKET, path }),
      method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data) },
      timeout: 20_000,
    }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (text += c));
      res.on("end", () => {
        if (res.statusCode !== 200) return reject(new Error(`dstack ${path} answered ${res.statusCode}`));
        try { resolve(JSON.parse(text) as T); } catch { reject(new Error(`dstack ${path} sent no JSON`)); }
      });
    });
    req.on("timeout", () => req.destroy(new Error(`dstack ${path} timed out`)));
    req.on("error", reject);
    req.end(data);
  });
}

/** 32 bytes only this app, on a genuine chip, can derive. The same path gives the same key after a restart. */
export async function chipKey(path: string): Promise<string> {
  const { key } = await call<{ key: string }>("/GetKey", { path, purpose: "paranoid gateway" });
  if (!/^[0-9a-f]{64}$/i.test(key)) throw new Error("dstack gave no key");
  return key.toLowerCase();
}

/** What the box runs: its app id and the compose file whose hash the boot log carries. */
export async function chipInfo(): Promise<{ appId: string; compose: string }> {
  const info = await call<{ app_id: string; tcb_info: string }>("/Info", {});
  const tcb = JSON.parse(info.tcb_info) as { app_compose?: string };
  if (!tcb.app_compose) throw new Error("dstack gave no compose");
  return { appId: info.app_id, compose: tcb.app_compose };
}

/** The statement a quote vouches for: this gateway's OHTTP key configuration, for this caller's nonce. */
export const statementOf = (keyConfigB64: string, nonce: string) =>
  `{"key_config":"${keyConfigB64}","nonce":"${nonce}","purpose":"paranoid.gateway.v1"}`;

/** A TDX quote whose report_data is SHA-256 of the statement (the rest zero), with its boot log. */
export async function chipQuote(statement: string): Promise<{ quote: string; eventLog: string; reportData: string }> {
  const reportData = createHash("sha256").update(statement).digest("hex");
  const q = await call<{ quote: string; event_log: string }>("/GetQuote", { report_data: reportData });
  return { quote: q.quote, eventLog: q.event_log, reportData };
}
