// Groth16 (BN254) verification for snarkjs proofs with @noble/curves: the gateway's only check.
// Accepts iff e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) = 1.
import { bn254 } from "@noble/curves/bn254";

const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const { Fp2, Fp12 } = bn254.fields;
type S = string | bigint;
const g1 = (p: S[]) => bn254.G1.ProjectivePoint.fromAffine({ x: BigInt(p[0]), y: BigInt(p[1]) });
const g2 = (p: S[][]) => bn254.G2.ProjectivePoint.fromAffine({
  x: Fp2.fromBigTuple([BigInt(p[0][0]), BigInt(p[0][1])]),
  y: Fp2.fromBigTuple([BigInt(p[1][0]), BigInt(p[1][1])]),
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function verifyGroth16(vk: any, publicSignals: S[], proof: any): boolean {
  try {
    if (publicSignals.length + 1 !== vk.IC.length) return false;
    const A = g1(proof.pi_a), B = g2(proof.pi_b), C = g1(proof.pi_c);
    for (const p of [A, C]) p.assertValidity();
    B.assertValidity();
    let acc = g1(vk.IC[0]);
    publicSignals.forEach((s, i) => {
      const v = BigInt(s);
      if (v >= R) throw new Error("public input out of field");
      if (v !== 0n) acc = acc.add(g1(vk.IC[i + 1]).multiply(v));
    });
    const gt = bn254.pairingBatch([
      { g1: A.negate(), g2: B },
      { g1: g1(vk.vk_alpha_1), g2: g2(vk.vk_beta_2) },
      { g1: acc, g2: g2(vk.vk_gamma_2) },
      { g1: C, g2: g2(vk.vk_delta_2) },
    ]);
    return Fp12.eql(gt, Fp12.ONE);
  } catch {
    return false;
  }
}
