"""
Lattice Key Derivation for ZKPoK Context.

Derives lattice-native key material (A_ZK, s, e, t_ZK) from the
KEM seed, enabling the ZKPoK to prove knowledge of the MLWE
secret key without modifying the existing KEM interface.

CRITICAL CONSTRAINT (per architectural decision):
  The secret key vector `s` MUST be the same vector used in the KEM.
  Domain separation ensures A_ZK is independent of A_KEM.

Key derivation flow:
  KEM seed (32 bytes)
    ├─→ rho = SHA3-256(seed || "eirn-zk-keysplit-rho")     → A_ZK expansion seed
    ├─→ sigma = SHA3-256(seed || "eirn-zk-keysplit-sigma")  → s, e generation seed
    │     ├─→ s = CBD_η(sigma, nonce=0..k-1)                → secret vector
    │     └─→ e = CBD_η(sigma, nonce=k..2k-1)               → error vector
    ├─→ seed_ZK = SHA3-256(rho || "eirn-zk-matrix-v1")     → A_ZK matrix seed
    └─→ t_ZK = A_ZK · s + e mod q                           → public vector
"""

import hashlib
from dataclasses import dataclass
from typing import Tuple, List

from .params import LatticeZKParams, DEFAULT_ZK_PARAMS
from .poly import Poly, PolyVec, PolyMat, poly_add, matvec_mul, polyvec_to_bytes
from .sampling import expand_matrix, sample_secret_vector


def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


# ═══════════════════════════════════════════════════════════════
# Lattice Key Material
# ═══════════════════════════════════════════════════════════════

@dataclass
class LatticePublicKey:
    """
    Public key for the lattice-native ZKPoK.

    Contains:
      rho:  32-byte seed for matrix expansion
      t:    Public vector t = A·s + e ∈ R_q^k
    """
    rho: bytes          # Matrix expansion seed (32 bytes)
    t: PolyVec          # Public vector (k polynomials)
    params: LatticeZKParams

    def to_bytes(self) -> bytes:
        return self.rho + polyvec_to_bytes(self.t, self.params.q)


@dataclass
class LatticeSecretKey:
    """
    Secret key for the lattice-native ZKPoK.

    Contains:
      s:    Secret vector ∈ R_q^l (coefficients in [-η, η])
      e:    Error vector ∈ R_q^k  (coefficients in [-η, η])
      rho:  Matrix expansion seed (for convenience)
      t:    Public vector (for convenience)
    """
    s: PolyVec          # Secret vector (l polynomials)
    e: PolyVec          # Error vector (k polynomials)
    rho: bytes          # Matrix seed
    t: PolyVec          # Public vector
    params: LatticeZKParams


# ═══════════════════════════════════════════════════════════════
# Key Derivation
# ═══════════════════════════════════════════════════════════════

def derive_lattice_keys(
    kem_seed: bytes,
    params: LatticeZKParams = DEFAULT_ZK_PARAMS,
) -> Tuple[LatticePublicKey, LatticeSecretKey]:
    """
    Derive lattice key material from the KEM seed.

    This is the bridge between the hash-simulated KEM and the
    lattice-native ZKPoK. The same KEM seed deterministically
    produces the lattice keys.

    Args:
        kem_seed: 32-byte secret key seed from Eirn-KEM KeyGen
        params: ZKPoK parameters

    Returns:
        (pk_zk, sk_zk): Lattice public and secret keys
    """
    # Step 1: Derive sub-seeds with domain separation
    rho = _sha3_256(kem_seed + b"eirn-zk-keysplit-rho")
    sigma = _sha3_256(kem_seed + b"eirn-zk-keysplit-sigma")

    # Step 2: Expand public matrix A_ZK from rho
    # (domain separation happens inside expand_matrix via "eirn-zk-matrix-v1")
    A = expand_matrix(rho, params)

    # Step 3: Sample secret vector s (l polynomials, coefficients in [-η, η])
    s = sample_secret_vector(sigma, nonce=0, dim=params.l, params=params)

    # Step 4: Sample error vector e (k polynomials, coefficients in [-η, η])
    e = sample_secret_vector(sigma, nonce=params.l, dim=params.k, params=params)

    # Step 5: Compute public vector t = A·s + e mod q
    As = matvec_mul(A, s, params.q, params.n)
    t = [
        poly_add(As[i], e[i], params.q)
        for i in range(params.k)
    ]

    pk = LatticePublicKey(rho=rho, t=t, params=params)
    sk = LatticeSecretKey(s=s, e=e, rho=rho, t=t, params=params)

    return pk, sk


def reconstruct_public_key(
    pk_zk: LatticePublicKey,
    params: LatticeZKParams = DEFAULT_ZK_PARAMS,
) -> Tuple[PolyMat, PolyVec]:
    """
    Reconstruct (A_ZK, t) from the public key.

    Used by the verifier to expand A from rho and retrieve t.
    """
    A = expand_matrix(pk_zk.rho, params)
    return A, pk_zk.t
