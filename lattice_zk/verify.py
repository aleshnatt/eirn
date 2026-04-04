"""
Lattice-Native ZKPoK Verifier.

Verifies a Lyubashevsky Σ-protocol proof of MLWE secret key knowledge.

Verification steps:
  1. Check response norm: ||z||∞ < γ₁ - β
  2. Reconstruct challenge: c = SampleInBall(c̃)
  3. Compute verifier's view: r = A·z - c·t mod q
  4. Recover commitment high bits: w₁' = UseHint(h, r, 2γ₂)
  5. Fiat-Shamir consistency: c̃ == H(w₁' || t || ctx)
  6. Hint weight check: #1's in h ≤ ω

This verifier is designed for FAIL-FAST operation:
  - The cheapest checks (norm, hint weight) are performed first
  - Matrix-vector multiplication (the expensive step) comes only
    after preliminary checks pass
  - This preserves the DoS-resilience property of the original KCP
"""

import hashlib
from typing import Optional

from .params import LatticeZKParams, DEFAULT_ZK_PARAMS
from .poly import (
    PolyVec, PolyMat,
    polyvec_sub, polyvec_norm_inf,
    matvec_mul, polyvec_to_bytes,
)
from .sampling import expand_matrix, sample_in_ball
from .rounding import (
    polyvec_use_hint, count_hint_ones, encode_w1,
)
from .prove import LatticeZKProof, _poly_vec_mul_by_challenge
from .keygen import LatticePublicKey


def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def lattice_verify(
    pk_zk: LatticePublicKey,
    ctx: bytes,
    proof: LatticeZKProof,
    params: LatticeZKParams = DEFAULT_ZK_PARAMS,
) -> bool:
    """
    Verify a Lattice-Native ZKPoK.

    Checks that the prover knows s such that t = A·s + e mod q.

    Args:
        pk_zk: Lattice public key (rho, t)
        ctx:   Session context (must match prover's context)
        proof: The lattice ZK proof (c̃, z, h)
        params: ZKPoK parameters

    Returns:
        True if proof is valid, False otherwise.

    Verification order (fail-fast):
      1. Hint weight (trivial check)
      2. Response norm (no arithmetic needed)
      3. Matrix-vector multiplication (expensive)
      4. Hint reconstruction
      5. Fiat-Shamir consistency
    """
    # ── Check 0: Hint weight ≤ ω (cheapest check) ──
    hint_ones = count_hint_ones(proof.hints)
    if hint_ones > params.omega:
        return False

    # ── Check 1: Response norm ||z||∞ < γ₁ - β ──
    z_norm = polyvec_norm_inf(proof.z, params.q)
    if z_norm >= params.gamma1 - params.beta:
        return False

    # ── Check 2: Reconstruct challenge c from c̃ ──
    c = sample_in_ball(proof.c_hash, params)

    # ── Check 3: Compute r = A·z - c·t mod q ──
    A = expand_matrix(pk_zk.rho, params)
    Az = matvec_mul(A, proof.z, params.q, params.n)
    ct = _poly_vec_mul_by_challenge(c, pk_zk.t, params)
    r = polyvec_sub(Az, ct, params.q)

    # ── Check 4: Recover w₁' using hints ──
    alpha = 2 * params.gamma2
    w1_prime = polyvec_use_hint(proof.hints, r, alpha, params.q)

    # ── Check 5: Fiat-Shamir consistency ──
    w1_bytes = encode_w1(w1_prime, params.q, alpha)
    t_bytes = polyvec_to_bytes(pk_zk.t, params.q)

    c_hash_expected = _sha3_256(
        params.proof_domain + w1_bytes + t_bytes + ctx
    )

    if proof.c_hash != c_hash_expected:
        return False

    return True
