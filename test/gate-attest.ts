// What the gateway proves when it runs on a confidential chip (gate/tee.ts, /api/gate/attest), checked
// against the dstack stand-in (test/dstack-stub.ts):
//   1. The key that opens sealed requests comes from the chip: an OHTTP seed handed in through the
//      settings is ignored, and the published key config is the one derived from the chip's key.
//   2. The quote vouches for exactly that key config and the caller's nonce: report_data is SHA-256 of
//      the statement, the rest of report_data is zero, and another nonce gives another quote.
//   3. The boot log replays to the quote's RTMR3 and its compose-hash event is SHA-256 of the compose
//      file the gateway returns.
//   4. A request sealed to the proven key goes through /api/ohttp and its sealed answer opens.
// Run: node test/dstack-stub.ts serve 41702, then the gateway with DSTACK_SIMULATOR_ENDPOINT pointing at it
// and PARANOID_OHTTP_SEED set to $ENV_SEED, then GATE=<gateway url> ENV_SEED=<same hex> node test/gate-attest.ts
import { createHash, randomBytes } from "node:crypto";
import { serverKeys, sealRequest } from "../web/lib/paranoid/ohttp.ts";
import { stubKey } from "./dstack-stub.ts";

const GATE = process.env.GATE ?? "http://127.0.0.1:47300";
let pass = 0, fail = 0;
const ok = (name: string, cond: boolean, detail = "") => { cond ? pass++ : fail++; console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : ": " + detail}`); };
const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
const sha = (algo: string, ...parts: Buffer[]) => createHash(algo).update(Buffer.concat(parts)).digest();
type Attest = { key_config: string; nonce: string; report_data: string; quote: string; event_log: string; app_compose: string; app_id: string };
const attest = async (nonce: string) => fetch(`${GATE}/api/gate/attest?nonce=${nonce}`).then(async (r) => ({ status: r.status, j: r.ok ? (await r.json()) as Attest : null }));

ok("a nonce that is not 32 bytes of hex is refused", (await attest("abc")).status === 400);
const n1 = randomBytes(32).toString("hex"), n2 = randomBytes(32).toString("hex");
const a = (await attest(n1)).j!, b = (await attest(n2)).j!;
ok("the gateway gives a proof", !!a && !!b);

// 1. the key comes from the chip
const published = b64(new Uint8Array(await (await fetch(`${GATE}/api/ohttp/config`)).arrayBuffer()));
const fromChip = b64((await serverKeys(stubKey("paranoid/ohttp/v1"))).config);
const fromSettings = b64((await serverKeys(process.env.ENV_SEED!)).config);
ok("the proven key is the published OHTTP key", a.key_config === published);
ok("the key is derived from the chip's key", a.key_config === fromChip);
ok("the seed in the settings is ignored", a.key_config !== fromSettings);

// 2. the quote vouches for this key and this nonce
const body = 48, q = Buffer.from(a.quote, "hex");
const statement = `{"key_config":"${a.key_config}","nonce":"${n1}","purpose":"paranoid.gateway.v1"}`;
const bound = sha("sha256", Buffer.from(statement)).toString("hex");
ok("report_data is SHA-256 of the statement", a.report_data === bound && q.subarray(body + 520, body + 552).toString("hex") === bound);
ok("the rest of report_data is zero", q.subarray(body + 552, body + 584).every((x) => x === 0));
ok("another nonce gives another quote", b.report_data !== a.report_data && b.key_config === a.key_config);

// 3. the boot log and the compose file
let rtmr3 = Buffer.alloc(48), compose = "";
let logOk = true;
for (const e of JSON.parse(a.event_log) as { imr: number; event_type: number; event: string; event_payload: string; digest: string }[]) {
  if (String(e.imr) !== "3") continue;
  const type = Buffer.alloc(4); type.writeUInt32LE(e.event_type);
  const d = sha("sha384", type, Buffer.from(":"), Buffer.from(e.event), Buffer.from(":"), Buffer.from(e.event_payload, "hex"));
  // The real dstack leaves `digest` empty on these events; the replay into RTMR3 is what binds them.
  logOk &&= !e.digest || d.toString("hex") === e.digest;
  rtmr3 = sha("sha384", rtmr3, d);
  if (e.event === "compose-hash") compose = e.event_payload;
}
ok("every boot log event that carries a digest matches it", logOk);
ok("the boot log replays to the quote's RTMR3", rtmr3.toString("hex") === q.subarray(body + 472, body + 520).toString("hex"));
ok("the compose file is the one in the boot log", sha("sha256", Buffer.from(a.app_compose)).toString("hex") === compose);

// 4. a request sealed to the proven key
const sealed = await sealRequest(Buffer.from(a.key_config, "base64"), { method: "GET", path: "/api/v1/models", headers: [], body: new Uint8Array() });
const r = await fetch(`${GATE}/api/ohttp`, { method: "POST", headers: { "content-type": "message/ohttp-req" }, body: sealed.wire as unknown as BodyInit });
const inner = r.ok ? await sealed.open(new Uint8Array(await r.arrayBuffer())) : null;
ok("a request sealed to the proven key is answered and its answer opens", inner?.status === 200 && JSON.parse(new TextDecoder().decode(inner.body)).object === "list", String(r.status));

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
