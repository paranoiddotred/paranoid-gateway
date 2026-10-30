// Seals a chat request to one Chutes TEE instance, so only that chip can read it (Chutes E2EE,
// github.com/chutesai/chutes-e2ee-transport). The instance made its ML-KEM-768 key inside the TEE;
// the browser encapsulates to it, derives a ChaCha20-Poly1305 key with HKDF-SHA256 (salt: the first
// 16 bytes of the KEM ciphertext), and sends KEM ciphertext || nonce || sealed gzip(JSON). The JSON
// carries a fresh response key, so the answer comes back sealed to this browser alone. Our gateway
// and the Chutes API only ever pass these bytes along.
import { ml_kem768 } from "../vendor/noble-post-quantum/ml-kem.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";

const KEM_CT = 1088;
const te = new TextEncoder(), td = new TextDecoder();
const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const keyFor = (secret: Uint8Array, kemCt: Uint8Array, info: string) => hkdf(sha256, secret, kemCt.slice(0, 16), te.encode(info), 32);

async function pipe(data: Uint8Array, stream: CompressionStream | DecompressionStream) {
  const out = new Response(new Blob([data as BlobPart]).stream().pipeThrough(stream as unknown as TransformStream<Uint8Array, Uint8Array>));
  return new Uint8Array(await out.arrayBuffer());
}

/** Seals `payload` to the instance key (base64). Keep `responseKey`: only it opens the answer. */
export async function sealToChip(instanceKeyB64: string, payload: Record<string, unknown>) {
  const response = ml_kem768.keygen();
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(unb64(instanceKeyB64));
  const body = te.encode(JSON.stringify({ ...payload, e2e_response_pk: b64(response.publicKey) }));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const sealed = chacha20poly1305(keyFor(sharedSecret, cipherText, "e2e-req-v1"), nonce).encrypt(await pipe(body, new CompressionStream("gzip")));
  const blob = new Uint8Array(KEM_CT + 12 + sealed.length);
  blob.set(cipherText, 0); blob.set(nonce, KEM_CT); blob.set(sealed, KEM_CT + 12);
  return { blob, responseKey: response.secretKey };
}

/** Opens a whole (non-streamed) sealed answer. */
export async function openFromChip(blob: Uint8Array, responseKey: Uint8Array): Promise<Record<string, unknown>> {
  const kemCt = blob.slice(0, KEM_CT), nonce = blob.slice(KEM_CT, KEM_CT + 12);
  const key = keyFor(ml_kem768.decapsulate(kemCt, responseKey), kemCt, "e2e-resp-v1");
  return JSON.parse(td.decode(await pipe(chacha20poly1305(key, nonce).decrypt(blob.slice(KEM_CT + 12)), new DecompressionStream("gzip"))));
}

/** A streamed answer: the `e2e_init` event gives the stream key, then each `e2e` event is one sealed SSE line. */
export const streamKey = (responseKey: Uint8Array, initB64: string) => {
  const kemCt = unb64(initB64);
  return keyFor(ml_kem768.decapsulate(kemCt, responseKey), kemCt, "e2e-stream-v1");
};
export const openChunk = (key: Uint8Array, chunkB64: string) => {
  const raw = unb64(chunkB64);
  return td.decode(chacha20poly1305(key, raw.slice(0, 12)).decrypt(raw.slice(12)));
};
