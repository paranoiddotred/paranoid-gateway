// Oblivious HTTP (RFC 9458) with binary HTTP messages (RFC 9292), the parts PARANOID needs.
// The browser seals a whole HTTP request to the gateway's public key and posts the sealed blob to a
// relay on different infrastructure; the relay sees only the caller's address and an opaque blob,
// and this server sees only the blob's contents and the relay's address. Works in the browser and
// in the Next.js node runtime (WebCrypto only, no node imports).
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

const KEM_ID = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const KDF_ID = 0x0001; // HKDF-SHA256
const AEAD_ID = 0x0001; // AES-128-GCM
const KEY_ID = 1;
const NK = 16; // AES-128-GCM key bytes
const NN = 12; // AES-128-GCM nonce bytes

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });

const te = new TextEncoder();
const td = new TextDecoder();
const cat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const u16 = (v: number) => new Uint8Array([v >> 8, v & 0xff]);

// ---- QUIC variable-length integers, the number coding BHTTP uses.

function varint(v: number): Uint8Array {
  if (v < 64) return new Uint8Array([v]);
  if (v < 16384) return new Uint8Array([0x40 | (v >> 8), v & 0xff]);
  if (v < 1 << 30) return new Uint8Array([0x80 | (v >>> 24), (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
  throw new Error("value too large");
}

class Reader {
  private d: Uint8Array;
  public at: number;
  constructor(d: Uint8Array, at = 0) { this.d = d; this.at = at; }
  varint(): number {
    const first = this.d[this.at];
    const len = 1 << (first >> 6);
    let v = first & 0x3f;
    for (let i = 1; i < len; i++) v = v * 256 + this.d[this.at + i];
    this.at += len;
    return v;
  }
  bytes(n: number): Uint8Array { const b = this.d.subarray(this.at, this.at + n); this.at += n; return b; }
  get left(): number { return this.d.length - this.at; }
}

const lenPrefixed = (b: Uint8Array) => cat(varint(b.length), b);

// ---- binary HTTP, known-length form only.

export type InnerRequest = { method: string; path: string; headers: [string, string][]; body: Uint8Array };
export type InnerResponse = { status: number; headers: [string, string][]; body: Uint8Array };

function fieldSection(headers: [string, string][]): Uint8Array {
  const lines = cat(...headers.map(([n, v]) => cat(lenPrefixed(te.encode(n.toLowerCase())), lenPrefixed(te.encode(v)))));
  return cat(varint(lines.length), lines);
}

function readFieldSection(r: Reader): [string, string][] {
  const end = r.varint() + r.at;
  const out: [string, string][] = [];
  while (r.at < end) {
    const name = td.decode(r.bytes(r.varint()));
    out.push([name, td.decode(r.bytes(r.varint()))]);
  }
  return out;
}

export function encodeRequest(q: InnerRequest): Uint8Array {
  return cat(
    varint(0), // known-length request
    lenPrefixed(te.encode(q.method)), lenPrefixed(te.encode("https")), lenPrefixed(te.encode("")), lenPrefixed(te.encode(q.path)),
    fieldSection(q.headers),
    lenPrefixed(q.body),
    varint(0), // empty trailer section
  );
}

export function decodeRequest(wire: Uint8Array): InnerRequest {
  const r = new Reader(wire);
  if (r.varint() !== 0) throw new Error("not a known-length request");
  const method = td.decode(r.bytes(r.varint()));
  r.bytes(r.varint()); // scheme
  r.bytes(r.varint()); // authority
  const path = td.decode(r.bytes(r.varint()));
  const headers = readFieldSection(r);
  const body = r.bytes(r.varint());
  return { method, path, headers, body: new Uint8Array(body) };
}

export function encodeResponse(p: InnerResponse): Uint8Array {
  return cat(varint(1), varint(p.status), fieldSection(p.headers), lenPrefixed(p.body), varint(0));
}

export function decodeResponse(wire: Uint8Array): InnerResponse {
  const r = new Reader(wire);
  if (r.varint() !== 1) throw new Error("not a known-length response");
  const status = r.varint();
  const headers = readFieldSection(r);
  const body = r.bytes(r.varint());
  return { status, headers, body: new Uint8Array(body) };
}

// ---- RFC 9458 encapsulation.

// ---- Chunked responses (draft-ietf-ohai-chunked-ohttp): a streamed answer is sealed piece by piece
// as it is written, so it reaches the browser through the relay while it is still coming. The head
// (status and headers) is the first sealed piece, then each piece of the body; the last piece is
// sealed as final, so a relay that cuts the stream short cannot pass off a shorter answer.

const CHUNKED_LABEL = "message/bhttp chunked response";
const FINAL = te.encode("final");
const NOT_FINAL = new Uint8Array();

/** Each piece's nonce: the response nonce XOR the piece's counter. */
function chunkNonce(base: Uint8Array, counter: number): Uint8Array {
  const n = base.slice();
  for (let i = NN - 1, c = counter; c > 0; i--, c = Math.floor(c / 256)) n[i] ^= c & 0xff;
  return n;
}

/** Pulls exact byte counts out of a stream that arrives in arbitrary pieces. */
class StreamReader {
  private buf = new Uint8Array();
  private src: ReadableStreamDefaultReader<Uint8Array>;
  constructor(src: ReadableStreamDefaultReader<Uint8Array>) { this.src = src; }
  private async more(): Promise<boolean> {
    const { done, value } = await this.src.read();
    if (!done) this.buf = cat(this.buf, value);
    return !done;
  }
  async take(n: number): Promise<Uint8Array> {
    while (this.buf.length < n) if (!(await this.more())) throw new Error("The sealed answer was cut short.");
    const b = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return b;
  }
  async varint(): Promise<number> {
    const first = (await this.take(1))[0];
    let v = first & 0x3f;
    for (const b of await this.take((1 << (first >> 6)) - 1)) v = v * 256 + b;
    return v;
  }
  async rest(): Promise<Uint8Array> {
    while (await this.more()) { /* read to the end */ }
    return this.take(this.buf.length);
  }
  cancel(reason?: unknown) { return this.src.cancel(reason); }
}

const hdr = () => cat(new Uint8Array([KEY_ID]), u16(KEM_ID), u16(KDF_ID), u16(AEAD_ID));
const requestInfo = (chunked: boolean) => cat(te.encode(chunked ? "message/bhttp chunked request" : "message/bhttp request"), new Uint8Array([0]), hdr());

/** The gateway's published key configuration (application/ohttp-keys). */
export function keyConfig(publicKey: Uint8Array): Uint8Array {
  return cat(new Uint8Array([KEY_ID]), u16(KEM_ID), publicKey, u16(4), u16(KDF_ID), u16(AEAD_ID));
}

export function parseKeyConfig(cfg: Uint8Array): { keyId: number; publicKey: Uint8Array } {
  const r = new Reader(cfg);
  const keyId = r.bytes(1)[0];
  const kem = (r.bytes(1)[0] << 8) | r.bytes(1)[0];
  if (kem !== KEM_ID) throw new Error("unexpected KEM");
  return { keyId, publicKey: new Uint8Array(r.bytes(32)) };
}

async function responseAead(enc: Uint8Array, exported: Uint8Array, responseNonce: Uint8Array) {
  const salt = cat(enc, responseNonce);
  const ikm = await crypto.subtle.importKey("raw", exported as BufferSource, "HKDF", false, ["deriveBits"]);
  const bits = async (info: string, len: number) =>
    new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: te.encode(info) as BufferSource }, ikm, len * 8));
  // HKDF here is Extract with `salt` then Expand with the label; WebCrypto's deriveBits does both.
  const key = await crypto.subtle.importKey("raw", (await bits("key", NK)) as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
  const nonce = await bits("nonce", NN);
  return { key, nonce };
}

/** Browser side: seal one request; the returned `open` unseals the matching response. A chunked request
 *  (message/ohttp-chunked-req) travels as one final piece and asks for a chunked answer. */
export async function sealRequest(configBytes: Uint8Array, q: InnerRequest, chunked = false) {
  const { publicKey } = parseKeyConfig(configBytes);
  const pk = await suite.kem.deserializePublicKey(publicKey as BufferSource);
  const sender = await suite.createSenderContext({ recipientPublicKey: pk, info: requestInfo(chunked) as BufferSource });
  const enc = new Uint8Array(sender.enc);
  const sealed = new Uint8Array(await sender.seal(encodeRequest(q) as BufferSource, (chunked ? FINAL : NOT_FINAL) as BufferSource));
  const wire = chunked ? cat(hdr(), enc, varint(0), sealed) : cat(hdr(), enc, sealed);
  const exported = new Uint8Array(await sender.export(te.encode("message/bhttp response") as BufferSource, NK));
  return {
    wire,
    async open(responseWire: Uint8Array): Promise<InnerResponse> {
      const responseNonce = responseWire.subarray(0, Math.max(NK, NN));
      const ct = responseWire.subarray(Math.max(NK, NN));
      const { key, nonce } = await responseAead(enc, exported, new Uint8Array(responseNonce));
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce as BufferSource }, key, ct as BufferSource));
      return decodeResponse(pt);
    },
    /** Opens a chunked response as it arrives: the head first, then a body stream of opened pieces. */
    async openChunked(stream: ReadableStream<Uint8Array>): Promise<{ status: number; headers: [string, string][]; body: ReadableStream<Uint8Array> }> {
      const exportedChunked = new Uint8Array(await sender.export(te.encode(CHUNKED_LABEL) as BufferSource, NK));
      const src = new StreamReader(stream.getReader());
      const { key, nonce } = await responseAead(enc, exportedChunked, new Uint8Array(await src.take(Math.max(NK, NN))));
      let counter = 0;
      const next = async () => {
        const len = await src.varint();
        const final = len === 0;
        const ct = final ? await src.rest() : await src.take(len);
        const iv = chunkNonce(nonce, counter++);
        const data = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: (final ? FINAL : NOT_FINAL) as BufferSource }, key, ct as BufferSource));
        return { data, final };
      };
      const first = await next();
      if (first.final) throw new Error("The sealed answer was cut short.");
      const head = decodeResponse(first.data);
      const body = new ReadableStream<Uint8Array>({
        async pull(c) {
          for (;;) {
            const { data, final } = await next();
            if (data.length) c.enqueue(data);
            if (final) return c.close();
            if (data.length) return;
          }
        },
        cancel: (reason) => src.cancel(reason),
      });
      return { status: head.status, headers: head.headers, body };
    },
  };
}

/** Server side: the key pair, derived from a secret seed so every instance agrees. */
export async function serverKeys(seedHex: string) {
  const ikm = Uint8Array.from(seedHex.match(/../g)!.map((h) => parseInt(h, 16)));
  const kp = await suite.kem.deriveKeyPair(ikm as BufferSource);
  const pub = new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey));
  return { keyPair: kp, config: keyConfig(pub) };
}

/** Server side: unseal one request; the returned `seal` (or `sealChunked`, for a chunked request) wraps
 *  the response for the same caller. */
export async function openRequest(keyPair: CryptoKeyPair, wire: Uint8Array, chunked = false) {
  const r = new Reader(wire);
  const sentHdr = r.bytes(7);
  if (sentHdr[0] !== KEY_ID) throw new Error("unknown key id");
  const enc = new Uint8Array(r.bytes(32));
  const recipient = await suite.createRecipientContext({ recipientKey: keyPair, enc: enc as BufferSource, info: requestInfo(chunked) as BufferSource });
  let plain: Uint8Array;
  if (!chunked) plain = new Uint8Array(await recipient.open(wire.subarray(r.at) as BufferSource));
  else {
    const parts: Uint8Array[] = [];
    for (;;) {
      const len = r.varint();
      const final = len === 0;
      parts.push(new Uint8Array(await recipient.open(r.bytes(final ? r.left : len) as BufferSource, (final ? FINAL : NOT_FINAL) as BufferSource)));
      if (final) break;
    }
    plain = cat(...parts);
  }
  const inner = decodeRequest(plain);
  const exported = new Uint8Array(await recipient.export(te.encode("message/bhttp response") as BufferSource, NK));
  return {
    inner,
    async seal(p: InnerResponse): Promise<Uint8Array> {
      const responseNonce = crypto.getRandomValues(new Uint8Array(Math.max(NK, NN)));
      const { key, nonce } = await responseAead(enc, exported, responseNonce);
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource }, key, encodeResponse(p) as BufferSource));
      return cat(responseNonce, ct);
    },
    /** Seals a response piece by piece as its body streams in. */
    async sealChunked(status: number, headers: [string, string][], body: ReadableStream<Uint8Array> | null): Promise<ReadableStream<Uint8Array>> {
      const exportedChunked = new Uint8Array(await recipient.export(te.encode(CHUNKED_LABEL) as BufferSource, NK));
      const responseNonce = crypto.getRandomValues(new Uint8Array(Math.max(NK, NN)));
      const { key, nonce } = await responseAead(enc, exportedChunked, responseNonce);
      let counter = 0;
      const piece = async (pt: Uint8Array, final: boolean) => {
        const iv = chunkNonce(nonce, counter++);
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: (final ? FINAL : NOT_FINAL) as BufferSource }, key, pt as BufferSource));
        return final ? cat(varint(0), ct) : cat(varint(ct.length), ct);
      };
      const head = await piece(encodeResponse({ status, headers, body: new Uint8Array() }), false);
      const reader = body?.getReader();
      return new ReadableStream<Uint8Array>({
        start(c) { c.enqueue(cat(responseNonce, head)); },
        async pull(c) {
          for (;;) {
            const r = reader ? await reader.read() : { done: true as const, value: undefined };
            if (r.done) { c.enqueue(await piece(new Uint8Array(), true)); return c.close(); }
            if (r.value.length) return c.enqueue(await piece(r.value, false));
          }
        },
        cancel: (reason) => reader?.cancel(reason),
      });
    },
  };
}
