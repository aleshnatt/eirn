"""
Sampling Functions for the Lattice-Native ZKPoK.

Implements:
  - Deterministic matrix expansion (A_ZK from seed)
  - Secret/error vector generation (CBD sampling)
  - Masking vector generation (uniform in [-γ₁+1, γ₁])
  - SampleInBall (sparse challenge polynomial)

Domain separation follows the user's architectural decision:
  seed_ZK = SHA3-256(rho || "eirn-zk-matrix-v1")

All randomness is derived from SHA3/SHAKE for reproducibility.
"""

import hashlib
import struct
from typing import List, Tuple

from .params import LatticeZKParams, DEFAULT_ZK_PARAMS
from .poly import Poly, PolyVec, PolyMat, poly_zero


# ═══════════════════════════════════════════════════════════════
# XOF / Hash Utilities
# ═══════════════════════════════════════════════════════════════

def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _shake256(data: bytes, length: int) -> bytes:
    return hashlib.shake_256(data).digest(length)


def _shake128(data: bytes, length: int) -> bytes:
    return hashlib.shake_128(data).digest(length)


# ═══════════════════════════════════════════════════════════════
# Matrix Expansion: A_ZK ∈ R_q^{k×l}
# ═══════════════════════════════════════════════════════════════

def expand_matrix(
    rho: bytes,
    params: LatticeZKParams = DEFAULT_ZK_PARAMS,
) -> PolyMat:
    """
    Expand the public matrix A_ZK from seed with domain separation.

    Per architectural decision:
      seed_ZK = SHA3-256(rho || "eirn-zk-matrix-v1")

    Each polynomial A[i][j] is expanded via SHAKE-128 seeded
    with (seed_ZK || i || j), sampling coefficients in [0, q).

    This mirrors Kyber/Dilithium's ExpandA but with Eirn-specific
    domain separation to ensure independence from the KEM matrix.
    """
    seed_zk = _sha3_256(rho + params.matrix_domain)

    A = []
    for i in range(params.k):
        row = []
        for j in range(params.l):
            # Per-entry seed: seed_ZK || row || col
            entry_seed = seed_zk + struct.pack('<BB', i, j)
            poly = _sample_uniform_poly(entry_seed, params.n, params.q)
            row.append(poly)
        A.append(row)
    return A


def _sample_uniform_poly(seed: bytes, n: int, q: int) -> Poly:
    """
    Sample a uniformly random polynomial in R_q via rejection sampling.

    Uses SHAKE-128 as XOF, sampling 3 bytes at a time.
    Reject values ≥ q (standard Kyber/Dilithium technique).
    """
    stream = _shake128(seed, n * 4)  # generous buffer
    coeffs = []
    offset = 0

    while len(coeffs) < n:
        if offset + 3 > len(stream):
            # Extend stream if needed (very unlikely)
            stream += _shake128(seed + len(stream).to_bytes(4, 'little'), n * 4)

        # Sample 3 bytes, mask to 23 bits (sufficient for q < 2^23)
        b0 = stream[offset]
        b1 = stream[offset + 1]
        b2 = stream[offset + 2]
        offset += 3

        val = b0 | (b1 << 8) | (b2 << 16)
        val &= 0x7FFFFF  # 23-bit mask

        if val < q:
            coeffs.append(val)

    return coeffs[:n]


# ═══════════════════════════════════════════════════════════════
# Secret / Error Sampling (Centered Binomial Distribution)
# ═══════════════════════════════════════════════════════════════

def sample_secret_vector(
    seed: bytes,
    nonce: int,
    dim: int,
    params: LatticeZKParams = DEFAULT_ZK_PARAMS,
) -> PolyVec:
    """
    Sample a secret/error vector with coefficients in [-η, η].

    Uses centered binomial distribution (CBD) following CRYSTALS-Kyber.
    Each polynomial is derived from SHAKE-256(seed || nonce + i).
    """
    vec = []
    for i in range(dim):
        poly_seed = _shake256(
            seed + struct.pack('<H', nonce + i),
            params.n * params.eta  # sufficient bytes for CBD
        )
        poly = _cbd(poly_seed, params.n, params.eta, params.q)
        vec.append(poly)
    return vec


def _cbd(buf: bytes, n: int, eta: int, q: int) -> Poly:
    """
    Centered Binomial Distribution sampling.

    For η=2: sample 4 bits, compute (b0+b1) - (b2+b3).
    Coefficients are in [-η, η] = [-2, 2].
    """
    coeffs = []

    if eta == 2:
        for i in range(n):
            byte_idx = i // 2
            if byte_idx >= len(buf):
                coeffs.append(0)
                continue
            b = buf[byte_idx]
            if i % 2 == 0:
                bits = b & 0x0F  # low nibble
            else:
                bits = (b >> 4) & 0x0F  # high nibble

            b0 = bits & 1
            b1 = (bits >> 1) & 1
            b2 = (bits >> 2) & 1
            b3 = (bits >> 3) & 1
            val = (b0 + b1) - (b2 + b3)
            coeffs.append(val % q)
    elif eta == 3:
        # CBD-3: 6 bits → (b0+b1+b2) - (b3+b4+b5)
        bits_stream = []
        for byte in buf:
            for bit_pos in range(8):
                bits_stream.append((byte >> bit_pos) & 1)

        for i in range(n):
            idx = i * 6
            if idx + 5 >= len(bits_stream):
                coeffs.append(0)
                continue
            a = sum(bits_stream[idx + j] for j in range(3))
            b = sum(bits_stream[idx + 3 + j] for j in range(3))
            val = (a - b) % q
            coeffs.append(val)
    else:
        raise ValueError(f"Unsupported η={eta}")

    return coeffs[:n]


# ═══════════════════════════════════════════════════════════════
# Masking Vector Sampling: y ∈ S_γ₁^{l×n}
# ═══════════════════════════════════════════════════════════════

def sample_masking_vector(
    seed: bytes,
    params: LatticeZKParams = DEFAULT_ZK_PARAMS,
) -> PolyVec:
    """
    Sample masking vector y with coefficients uniform in [-γ₁+1, γ₁].

    Used as the commitment randomness in the Σ-protocol.
    y must be kept secret; if revealed, it leaks information about s.
    """
    import os
    y = []
    for i in range(params.l):
        # Per-polynomial randomness from SHAKE-256
        poly_seed = _shake256(
            seed + b"mask" + struct.pack('<H', i) + os.urandom(16),
            params.n * 3  # 3 bytes per coefficient
        )
        poly = _sample_uniform_range(
            poly_seed, params.n, params.gamma1, params.q
        )
        y.append(poly)
    return y


def _sample_uniform_range(
    buf: bytes, n: int, gamma1: int, q: int
) -> Poly:
    """
    Sample coefficients uniformly in [-γ₁+1, γ₁].

    Map 3-byte samples to [0, 2γ₁) then shift to [-γ₁+1, γ₁].
    """
    coeffs = []
    range_size = 2 * gamma1  # number of possible values

    for i in range(n):
        if 3 * i + 2 < len(buf):
            val = buf[3*i] | (buf[3*i+1] << 8) | (buf[3*i+2] << 16)
            val = val % range_size  # map to [0, 2γ₁)
            coeff = val - gamma1 + 1  # shift to [-γ₁+1, γ₁]
            # Store in [0, q) representation
            coeffs.append(coeff % q)
        else:
            coeffs.append(0)

    return coeffs


# ═══════════════════════════════════════════════════════════════
# Challenge Sampling: SampleInBall(c̃, τ)
# ═══════════════════════════════════════════════════════════════

def sample_in_ball(
    seed: bytes,
    params: LatticeZKParams = DEFAULT_ZK_PARAMS,
) -> Poly:
    """
    Sample a challenge polynomial c ∈ B_τ ⊂ R_q.

    c has exactly τ nonzero coefficients, each ±1.
    Follows the Dilithium SampleInBall algorithm:

    1. Use SHAKE-256(seed) to generate pseudorandom bytes.
    2. First 8 bytes → 64 sign bits.
    3. For i = n-τ to n-1:
       - Sample j uniform in [0, i] via rejection
       - Swap c[i] ↔ c[j]
       - Set c[i] = ±1 based on sign bit

    This produces a uniformly random weight-τ polynomial.
    """
    n = params.n
    tau = params.tau
    q = params.q

    # Generate pseudorandom stream
    stream = _shake256(seed, 8 + tau * 2)  # generous buffer

    c = [0] * n

    # Extract sign bits from first 8 bytes (64 bits)
    signs = int.from_bytes(stream[:8], 'little')

    offset = 8
    for i in range(n - tau, n):
        # Sample j ∈ [0, i] via rejection
        while True:
            if offset >= len(stream):
                stream += _shake256(seed + offset.to_bytes(4, 'little'), tau * 2)
            j = stream[offset]
            offset += 1
            if j <= i:
                break

        c[i] = c[j]
        # Set c[j] = ±1 based on sign bit
        sign_bit = signs & 1
        signs >>= 1
        c[j] = (q - 1) if sign_bit else 1  # -1 mod q or +1

    return c
