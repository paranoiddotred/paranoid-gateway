// Rate-limit nullifier math over the BN254 scalar field.
// Every paid request reveals one point (x, y) on the user's secret line y = a0 + a1 * x.
// One point says nothing about a0. Two different points on the same line (same ticket)
// give the line away, and a0 is the identity secret that the program slashes with.

export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const mod = (a: bigint) => ((a % P) + P) % P;

function inv(a: bigint): bigint {
  let [r0, r1, s0, s1] = [mod(a), P, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return mod(s0);
}

/** Recovers the identity secret a0 from two shares on the same line. */
export function recoverSecret(x1: bigint, y1: bigint, x2: bigint, y2: bigint): bigint {
  if (mod(x1) === mod(x2)) throw new Error("same x: these two shares are the same request");
  const a1 = mod((y1 - y2) * inv(x1 - x2));
  return mod(y1 - a1 * x1);
}
