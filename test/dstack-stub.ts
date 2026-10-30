// A stand-in for the dstack guest API (/var/run/dstack.sock) for local tests: GetKey derives keys from a
// fixed test root, Info names a test compose file, and GetQuote returns a TDX v4 quote laid out like the real
// one, with report_data where the chip puts it and RTMR3 equal to the replayed boot log. It carries no Intel
// signature, so the browser's Intel check fails on it by design; everything else can be checked.
import { createServer } from "node:http";
import { createHash, createHmac } from "node:crypto";

export const STUB_ROOT = "paranoid-test-root";
export const STUB_COMPOSE = JSON.stringify({ manifest_version: 2, name: "paranoid-gateway", runner: "docker-compose", docker_compose_file: "services:\n  gateway:\n    image: paranoid-gateway@sha256:test\n" });
export const APP_ID = "0123456789abcdef0123456789abcdef01234567";
export const stubKey = (path: string) => createHmac("sha256", STUB_ROOT).update(path).digest("hex");

const sha384 = (...parts: Buffer[]) => createHash("sha384").update(Buffer.concat(parts)).digest();
const EVENT_TYPE = 0x08000001;
function eventOf(event: string, payload: Buffer) {
  const type = Buffer.alloc(4); type.writeUInt32LE(EVENT_TYPE);
  const digest = sha384(type, Buffer.from(":"), Buffer.from(event), Buffer.from(":"), payload);
  return { imr: 3, event_type: EVENT_TYPE, event, event_payload: payload.toString("hex"), digest: digest.toString("hex") };
}
export const STUB_LOG = [
  eventOf("app-id", Buffer.from(APP_ID, "hex")),
  eventOf("compose-hash", createHash("sha256").update(STUB_COMPOSE).digest()),
  eventOf("instance-id", Buffer.from("aa".repeat(20), "hex")),
  eventOf("boot-mr-done", Buffer.alloc(0)),
];

function quoteFor(reportData: Buffer) {
  const body = 48, q = Buffer.alloc(body + 584 + 4);
  q.writeUInt16LE(4, 0); q.writeUInt32LE(0x81, 4);
  let rtmr3 = Buffer.alloc(48);
  for (const e of STUB_LOG) rtmr3 = sha384(rtmr3, Buffer.from(e.digest, "hex"));
  rtmr3.copy(q, body + 472);
  reportData.copy(q, body + 520);
  return q.toString("hex");
}

export function startDstackStub(port: number) {
  const server = createServer((req, res) => {
    let text = "";
    req.on("data", (c) => (text += c));
    req.on("end", () => {
      const body = text ? JSON.parse(text) : {};
      res.setHeader("content-type", "application/json");
      if (req.url === "/GetKey") return res.end(JSON.stringify({ key: stubKey(String(body.path)), signature_chain: [] }));
      if (req.url === "/Info") return res.end(JSON.stringify({ app_id: APP_ID, tcb_info: JSON.stringify({ app_compose: STUB_COMPOSE }) }));
      if (req.url === "/GetQuote") {
        const rd = Buffer.alloc(64); Buffer.from(String(body.report_data), "hex").copy(rd);
        return res.end(JSON.stringify({ quote: quoteFor(rd), event_log: JSON.stringify(STUB_LOG), report_data: rd.toString("hex") }));
      }
      res.statusCode = 404; res.end("{}");
    });
  });
  return new Promise<{ close: () => void }>((r) => server.listen(port, "127.0.0.1", () => r({ close: () => server.close() })));
}

// Standalone: node test/dstack-stub.ts serve [port]
if (process.argv[2] === "serve") {
  const port = Number(process.argv[3] ?? 41702);
  await startDstackStub(port);
  console.log(`dstack stub on ${port}`);
}
