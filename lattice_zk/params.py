"""
Lattice-Native ZKPoK Parameters.

Adapted from CRYSTALS-Dilithium Level 2 for Eirn-512 (k=l=2).
These parameters govern the Lyubashevsky rejection sampling
Σ-protocol that proves knowledge of the MLWE secret key.

Reference:
  Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Seiler, Stehlé.
  "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme."
  TCHES 2018.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class LatticeZKParams:
    """Parameter set for the Lattice-Native ZKPoK."""
    name: str

    # Ring parameters
    n: int          # Polynomial degree (X^n + 1 cyclotomic)
    q: int          # Modulus (NTT-friendly prime)

    # Module dimensions
    k: int          # Rows of A / dimension of t (public key vector)
    l: int          # Cols of A / dimension of s,y,z (secret/masking vector)

    # Secret generation
    eta: int        # Secret coefficient bound: |s_i|, |e_i| ≤ η

    # Rejection sampling parameters
    gamma1: int     # Masking range: y_i ∈ [-γ₁+1, γ₁]
    gamma2: int     # Rounding parameter for HighBits/LowBits

    # Challenge parameters
    tau: int        # Challenge weight: c has exactly τ nonzero coefficients (±1)

    # Derived bounds
    beta: int       # β = τ·η — upper bound on ||c·s||∞

    # Hint parameters
    omega: int      # Maximum number of 1's in the hint vector

    # Domain separation
    matrix_domain: bytes    # Prefix for A_ZK matrix expansion
    proof_domain: bytes     # Prefix for Fiat-Shamir challenge

    @property
    def q_half(self) -> int:
        """Centered representation bound: -(q-1)/2."""
        return (self.q - 1) // 2


# ═══════════════════════════════════════════════════════════════
# Eirn-ZKP-512: Dilithium-2 adapted for module rank k=l=2
# ═══════════════════════════════════════════════════════════════
#
# Security: ~128-bit classical, ~64-bit quantum (NIST Level 1)
#
# Key relation: t = A·s + e mod q, where ||s||∞,||e||∞ ≤ η
#
# Proof size: ~1,266 bytes
#   c̃:  32 bytes (challenge hash)
#   z:   2 × 256 × 18 / 8 = 1,152 bytes (response vector)
#   h:   ≤ ω + k = 82 bytes (hint)
#
ZKPARAMS_512 = LatticeZKParams(
    name="Eirn-ZKP-512",
    n=256,
    q=8380417,          # 2^23 - 2^13 + 1, NTT-friendly
    k=2,
    l=2,
    eta=2,
    gamma1=2**17,       # 131072
    gamma2=95232,       # (q-1)/88 = (8380416)/88 = 95232
    tau=39,             # Challenge weight
    beta=78,            # τ·η = 39·2 = 78
    omega=80,           # Max hint ones
    matrix_domain=b"eirn-zk-matrix-v1",
    proof_domain=b"eirn-zk-challenge-v1",
)


# ═══════════════════════════════════════════════════════════════
# Eirn-ZKP-768: For Eirn-768 (k=l=3, NIST Level 3)
# ═══════════════════════════════════════════════════════════════
ZKPARAMS_768 = LatticeZKParams(
    name="Eirn-ZKP-768",
    n=256,
    q=8380417,
    k=3,
    l=3,
    eta=2,
    gamma1=2**19,       # 524288 — larger masking for k=3
    gamma2=95232,
    tau=49,
    beta=98,            # τ·η = 49·2
    omega=96,
    matrix_domain=b"eirn-zk-matrix-v1",
    proof_domain=b"eirn-zk-challenge-v1",
)

DEFAULT_ZK_PARAMS = ZKPARAMS_512
