// PARANOID client SDK: the member secret, the member tree, request proofs and the API key format.
// Runs the same in the browser and in Node. Mirrors engine/circuits/request.circom `Request(20, 4)` (v2, question packs)
// and engine/programs/paranoid/src/merkle.rs (circomlib Poseidon, big-endian 32-byte fields).
import { poseidon1, poseidon2, poseidon3 } from "./poseidon.ts";

export const DEPTH = 20;
export const W = 4;
export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const toHex = (v: bigint) => v.toString(16).padStart(64, "0");
export const fieldToBytes = (v: bigint) => Uint8Array.from(toHex(v).match(/../g)!.map((h) => parseInt(h, 16)));
export const bytesToField = (b: Uint8Array) => BigInt("0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("") || "0");

/** A random non-zero field element (31 random bytes, so always below P). */
export function randomField(): bigint {
  const b = new Uint8Array(31);
  crypto.getRandomValues(b);
  const v = bytesToField(b);
  return v === 0n ? 1n : v;
}

export const commitmentOf = (secret: bigint) => poseidon1([secret]);
/** leaf = Poseidon(commitment, last valid day, tickets bought), as in engine/circuits/request.circom. */
/** The circuit's one namespace, Poseidon(0, "paranoid.v2"), and the nullifier of ticket `i`. */
export const EXTERNAL = poseidon2([0n, 0x706172616e6f69642e7632n]);
export const ticketNullifier = (secret: bigint, i: number) => poseidon1([poseidon3([secret, EXTERNAL, BigInt(i)])]);

export const leafOf = (commitment: bigint, endEpoch: number, questions: number) => poseidon3([commitment, BigInt(endEpoch), BigInt(questions)]);

const ZEROS: bigint[] = [0n];
for (let i = 0; i < DEPTH; i++) ZEROS.push(poseidon2([ZEROS[i], ZEROS[i]]));

export type Tree = { root: bigint; path: (index: number) => { pathElements: bigint[]; pathIndices: number[] } };

/** Builds the member tree from its non-empty leaves (index -> leaf). Removed members are simply absent. */
export function buildTree(leaves: Map<number, bigint>): Tree {
  const levels: Map<number, bigint>[] = [new Map([...leaves].filter(([, v]) => v !== 0n))];
  for (let i = 0; i < DEPTH; i++) {
    const next = new Map<number, bigint>();
    for (const k of levels[i].keys()) {
      const p = k >> 1;
      if (next.has(p)) continue;
      next.set(p, poseidon2([levels[i].get(2 * p) ?? ZEROS[i], levels[i].get(2 * p + 1) ?? ZEROS[i]]));
    }
    levels.push(next);
  }
  return {
    root: levels[DEPTH].get(0) ?? ZEROS[DEPTH],
    path(index: number) {
      const pathElements: bigint[] = [];
      const pathIndices: number[] = [];
      for (let i = 0; i < DEPTH; i++) {
        pathElements.push(levels[i].get(index ^ 1) ?? ZEROS[i]);
        pathIndices.push(index & 1);
        index >>= 1;
      }
      return { pathElements, pathIndices };
    },
  };
}

/** Runs snarkjs `groth16.fullProve` on the circuit artifacts. Node passes the snarkjs module; the
 *  browser passes window.snarkjs loaded from /zk/snarkjs.min.js. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Prover = (input: Record<string, unknown>) => Promise<{ proof: any; publicSignals: string[] }>;

export type Spend = {
  root: bigint; epoch: number; x: bigint; limit: number; weight: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  proof: any; nullifiers: bigint[]; ys: bigint[];
};

/** Proves "a member still valid on day `epoch` spends its tickets [start, start + weight) on message x".
 *  Tickets never come back: `start` must be past every ticket this member ever used. */
export async function proveSpend(a: {
  secret: bigint; endEpoch: number; questions: number; leafIndex: number; tree: Tree;
  epoch: number; limit: number; start: number; weight: number; x: bigint;
}, prove: Prover): Promise<Spend> {
  if (a.x === 0n) throw new Error("x must not be zero: y would equal the secret");
  const { pathElements, pathIndices } = a.tree.path(a.leafIndex);
  const input = {
    root: a.tree.root.toString(), epoch: a.epoch, x: a.x.toString(), limit: a.limit, weight: a.weight,
    secret: a.secret.toString(), endEpoch: a.endEpoch, questions: a.questions, start: a.start,
    pathElements: pathElements.map(String), pathIndices,
  };
  const { proof, publicSignals } = await prove(input);
  return fromSignals(proof, publicSignals.map(BigInt));
}

/** snarkjs public signal order: nullifiers[4], ys[4], root, epoch, x, limit, weight. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function fromSignals(proof: any, s: bigint[]): Spend {
  const weight = Number(s[12]);
  return {
    nullifiers: s.slice(0, weight), ys: s.slice(W, W + weight),
    root: s[8], epoch: Number(s[9]), x: s[10], limit: Number(s[11]), weight, proof,
  };
}

export function toSignals(sp: Spend): string[] {
  const pad = (a: bigint[]) => [...a, ...Array(W - a.length).fill(0n)];
  return [...pad(sp.nullifiers), ...pad(sp.ys), sp.root, BigInt(sp.epoch), sp.x, BigInt(sp.limit), BigInt(sp.weight)].map(String);
}

// ---- API key: one or more spends that share root, epoch, limit and x, packed into a bearer token.
// Layout: "sk-paranoid-" + base64url( 1 | n | root 32 | epoch 4 | limit 2 | x 32 | n * (weight 1 | proof 256 | weight * (nullifier 32 | y 32)) )

const PREFIX = "sk-paranoid-";

function b64url(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64url(s: string): Uint8Array {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(t + "===".slice((t.length + 3) % 4)), (c) => c.charCodeAt(0));
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const proofFields = (p: any): bigint[] => [p.pi_a[0], p.pi_a[1], p.pi_b[0][0], p.pi_b[0][1], p.pi_b[1][0], p.pi_b[1][1], p.pi_c[0], p.pi_c[1]].map(BigInt);
const proofFrom = (f: bigint[]) => ({
  pi_a: [f[0], f[1], 1n].map(String),
  pi_b: [[f[2], f[3]], [f[4], f[5]], [1n, 0n]].map((r) => r.map(String)),
  pi_c: [f[6], f[7], 1n].map(String),
  protocol: "groth16", curve: "bn128",
});

export function packKey(spends: Spend[]): string {
  const h = spends[0];
  for (const s of spends) if (s.root !== h.root || s.epoch !== h.epoch || s.limit !== h.limit || s.x !== h.x) throw new Error("spends in one key must share root, epoch, limit and x");
  const parts: Uint8Array[] = [Uint8Array.of(1, spends.length), fieldToBytes(h.root), u32(h.epoch), Uint8Array.of(h.limit >> 8, h.limit & 255), fieldToBytes(h.x)];
  for (const s of spends) {
    parts.push(Uint8Array.of(s.weight), ...proofFields(s.proof).map(fieldToBytes));
    for (let j = 0; j < s.weight; j++) parts.push(fieldToBytes(s.nullifiers[j]), fieldToBytes(s.ys[j]));
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return PREFIX + b64url(out);
}

function u32(v: number) { return Uint8Array.of(v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255); }

export function unpackKey(key: string): Spend[] {
  if (!key.startsWith(PREFIX)) throw new Error("not a PARANOID key");
  const b = unb64url(key.slice(PREFIX.length));
  let o = 0;
  const take = (n: number) => { if (o + n > b.length) throw new Error("key is cut short"); const r = b.subarray(o, o + n); o += n; return r; };
  const field = () => bytesToField(take(32));
  const [version, n] = take(2);
  if (version !== 1 || n < 1 || n > 16) throw new Error("unknown key version");
  const root = field();
  const e = take(4);
  const epoch = ((e[0] << 24) | (e[1] << 16) | (e[2] << 8) | e[3]) >>> 0;
  const l = take(2);
  const limit = (l[0] << 8) | l[1];
  const x = field();
  const spends: Spend[] = [];
  for (let i = 0; i < n; i++) {
    const weight = take(1)[0];
    if (weight < 1 || weight > W) throw new Error("bad weight");
    const proof = proofFrom(Array.from({ length: 8 }, field));
    const nullifiers: bigint[] = [], ys: bigint[] = [];
    for (let j = 0; j < weight; j++) { nullifiers.push(field()); ys.push(field()); }
    spends.push({ root, epoch, x, limit, weight, proof, nullifiers, ys });
  }
  if (o !== b.length) throw new Error("key has trailing bytes");
  return spends;
}
