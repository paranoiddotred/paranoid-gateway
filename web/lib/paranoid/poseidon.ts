// Poseidon over BN254 with circomlib's parameters (inputs 1, 2 and 3), the hash the circuit and the
// program use. Vendored from poseidon-lite 0.3.0 (MIT, github.com/vimwitch/poseidon-lite).
import K from "./poseidon-constants.json" with { type: "json" };

const F = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const N_ROUNDS_F = 8;
const N_ROUNDS_P = [56, 57, 56];

const decode = (s: string) => BigInt("0x" + Array.from(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)), (x) => x.toString(16).padStart(2, "0")).join(""));
const load = (k: { C: string[]; M: string[][] }) => ({ C: k.C.map(decode), M: k.M.map((r) => r.map(decode)) });
const P1 = load(K.t2), P2 = load(K.t3), P3 = load(K.t4); // t4 added from circomlibjs poseidon_constants.json

const pow5 = (v: bigint) => { const o = v * v; return (v * o * o) % F; };

function poseidon(inputs: bigint[], { C, M }: { C: bigint[]; M: bigint[][] }): bigint {
  const t = inputs.length + 1;
  const nP = N_ROUNDS_P[t - 2];
  let state = [0n, ...inputs.map((x) => ((x % F) + F) % F)];
  for (let x = 0; x < N_ROUNDS_F + nP; x++) {
    for (let y = 0; y < t; y++) {
      state[y] = state[y] + C[x * t + y];
      if (x < N_ROUNDS_F / 2 || x >= N_ROUNDS_F / 2 + nP || y === 0) state[y] = pow5(state[y]);
    }
    state = M.map((row) => row.reduce((acc, m, i) => acc + m * state[i], 0n) % F);
  }
  return state[0];
}

export const poseidon1 = (a: [bigint]) => poseidon(a, P1);
export const poseidon2 = (a: [bigint, bigint]) => poseidon(a, P2);
export const poseidon3 = (a: [bigint, bigint, bigint]) => poseidon(a, P3);
