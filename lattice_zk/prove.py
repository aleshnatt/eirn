"""
Lattice-Native ZKPoK Prover.

Implements Lyubashevsky's rejection-sampling Σ-protocol over
the MLWE key derivation relation:

  Relation: { (pk=(A,t), sk=(s,e)) | t = A·s + e mod q, ||s||∞,||e||∞ ≤ η }

Protocol:
  1. Sample masking vector y ← S_γ₁^l
  2. Compute commitment w = A·y mod q
  3. Extract w₁ = HighBits(w, 2γ₂)
  4. Fiat-Shamir challenge: c̃ = H(w₁ || t || ctx)
  5. Expand challenge: c = SampleInBall(c̃, τ)
  6. Compute response: z = y + c·s
  7. Rejection sampling:
     - Abort if ||z||∞ ≥ γ₁ - β
     - Abort if ||LowBits(A·z - c·t)||∞ ≥ γ₂ - β
  8. Compute hint: h = MakeHint(-c·e, w, 2γ₂)
  9. Output proof π = (c̃, z, h)

Soundness: An extractor can recover s from two accepting
           transcripts with different challenges (special soundness).
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Optional, List, Tuple

from .params import LatticeZKParams, DEFAULT_ZK_PARAMS
from .poly import (
    Poly, PolyVec, PolyMat,
    poly_zero, poly_mul, poly_add, poly_sub, poly_neg,
    polyvec_add, polyvec_sub, polyvec_neg, polyvec_norm_inf,
    matvec_mul, encode_z, polyvec_to_bytes,
)
from .sampling import (
    expand_matrix, sample_masking_vector, sample_in_ball,
)
from .rounding import (
    polyvec_high_bits, polyvec_low_bits_norm_inf,
    polyvec_make_hint, count_hint_ones,
    encode_w1, encode_hints,
)
from .keygen import LatticeSecretKey, LatticePublicKey


def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


# ═══════════════════════════════════════════════════════════════
# Proof Structure
# ═══════════════════════════════════════════════════════════════

@dataclass
class LatticeZKProof:
    """
    Lattice-native Zero-Knowledge Proof of Knowledge.

    Fields:
      c_hash:  Challenge hash c̃ (32 bytes)
      z:       Response vector (l polynomials, each coeff ∈ [-γ₁+β, γ₁-β])
      hints:   Verification hints (list of k hint vectors)

    Total proof size: ~1,266 bytes for Eirn-ZKP-512
    """
    c_hash: bytes               # 32 bytes — Fiat-Shamir challenge hash
    z: PolyVec                  # l polynomials — response vector
    hints: List[List[int]]      # k × n hint bits
    params: LatticeZKParams

    def to_bytes(self) -> bytes:
        """Serialize proof to bytes."""
        buf = bytearray()
        buf.extend(self.c_hash)  # 32 bytes
        buf.extend(encode_z(self.z, self.params.gamma1, self.params.n, self.params.q))
        buf.extend(encode_hints(
            self.hints, self.params.omega, self.params.k
        ))
        return bytes(buf)

    def proof_size(self) -> int:
        """Return proof size in bytes."""
        return len(self.to_bytes())

    def __repr__(self) -> str:
        size = self.proof_size()
        return (
            f"LatticeZKProof(\n"
            f"  c_hash={self.c_hash.hex()[:16]}...,\n"
            f"  z_norm_inf={polyvec_norm_inf(self.z, self.params.q)},\n"
            f"  hint_ones={count_hint_ones(self.hints)},\n"
            f"  size={size} bytes\n"
            f")"
        )


# ═══════════════════════════════════════════════════════════════
# Prover
# ═══════════════════════════════════════════════════════════════

def lattice_prove(
    sk_zk: LatticeSecretKey,
    ctx: bytes,
    params: LatticeZKParams = DEFAULT_ZK_PARAMS,
    max_attempts: int = 256,
) -> Optional[LatticeZKProof]:
    """
    Generate a Lattice-Native ZKPoK.

    Proves knowledge of s such that t = A·s + e mod q.

    Args:
        sk_zk: Lattice secret key containing (s, e, rho, t)
        ctx:   Session context (binds proof to handshake/ratchet)
        params: ZKPoK parameters
        max_attempts: Maximum rejection sampling iterations

    Returns:
        LatticeZKProof on success, None if max_attempts exceeded.

    Expected iterations: ~4 (for Dilithium-2 parameters)
    """
    # Expand public matrix from rho
    A = expand_matrix(sk_zk.rho, params)

    s = sk_zk.s
    e = sk_zk.e
    t = sk_zk.t

    alpha = 2 * params.gamma2  # rounding parameter

    # Encode t for hashing (fixed across attempts)
    t_bytes = polyvec_to_bytes(t, params.q)

    for attempt in range(max_attempts):
        # ── Step 1: Sample masking vector y ──
        y_seed = os.urandom(32)
        y = sample_masking_vector(y_seed, params)

        # ── Step 2: Commitment w = A·y mod q ──
        w = matvec_mul(A, y, params.q, params.n)

        # ── Step 3: Extract high bits w₁ = HighBits(w, 2γ₂) ──
        w1 = polyvec_high_bits(w, alpha, params.q)

        # ── Step 4: Fiat-Shamir challenge hash ──
        w1_bytes = encode_w1(w1, params.q, alpha)
        c_hash = _sha3_256(
            params.proof_domain + w1_bytes + t_bytes + ctx
        )

        # ── Step 5: Expand challenge c = SampleInBall(c̃) ──
        c = sample_in_ball(c_hash, params)

        # ── Step 6: Response z = y + c·s ──
        # Compute c·s_i for each polynomial in s
        cs = _poly_vec_mul_by_challenge(c, s, params)
        z = polyvec_add(y, cs, params.q)

        # ── Step 7a: Rejection check ||z||∞ < γ₁ - β ──
        z_norm = polyvec_norm_inf(z, params.q)
        if z_norm >= params.gamma1 - params.beta:
            continue  # REJECT — restart

        # ── Step 7b: Low-bits check ──
        # Compute A·z - c·t (what verifier will compute)
        Az = matvec_mul(A, z, params.q, params.n)
        ct = _poly_vec_mul_by_challenge(c, t, params)
        Az_ct = polyvec_sub(Az, ct, params.q)

        r0_norm = polyvec_low_bits_norm_inf(Az_ct, alpha, params.q)
        if r0_norm >= params.gamma2 - params.beta:
            continue  # REJECT — restart

        # ── Step 8: Compute hints ──
        # h = MakeHint(-c·e, w, 2γ₂)
        # -c·e is the perturbation: w' = w - c·e (verifier's view)
        ce = _poly_vec_mul_by_challenge(c, e, params)
        neg_ce = polyvec_neg(ce, params.q)

        hints = polyvec_make_hint(neg_ce, w, alpha, params.q)

        # ── Step 9: Check hint weight ──
        if count_hint_ones(hints) > params.omega:
            continue  # REJECT — too many hints

        # ── SUCCESS: Return proof ──
        return LatticeZKProof(
            c_hash=c_hash,
            z=z,
            hints=hints,
            params=params,
        )

    # Should not reach here with reasonable parameters (~4 attempts expected)
    return None


# ═══════════════════════════════════════════════════════════════
# Helper: Challenge × Vector multiplication
# ═══════════════════════════════════════════════════════════════

def _poly_vec_mul_by_challenge(
    c: Poly, v: PolyVec, params: LatticeZKParams
) -> PolyVec:
    """
    Multiply each polynomial in vector v by the challenge polynomial c.

    Returns [c·v[0], c·v[1], ..., c·v[k-1]] in R_q.
    """
    return [poly_mul(c, vi, params.q, params.n) for vi in v]
