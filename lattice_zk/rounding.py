"""
Rounding Functions for the Lattice-Native ZKPoK.

Implements the Decompose / HighBits / LowBits / MakeHint / UseHint
primitives from CRYSTALS-Dilithium. These functions enable the
verifier to reconstruct the commitment's high-order bits without
knowing the error term, using compact hints.

Reference: CRYSTALS-Dilithium specification, Section 2.4.
"""

from typing import List, Tuple

from .params import LatticeZKParams, DEFAULT_ZK_PARAMS
from .poly import Poly, PolyVec, mod_centered


# ═══════════════════════════════════════════════════════════════
# Core Decompose: r → (r₁, r₀) where r = r₁·α + r₀
# ═══════════════════════════════════════════════════════════════

def decompose(r: int, alpha: int, q: int) -> Tuple[int, int]:
    """
    Decompose r mod q into (high, low) parts.

    Returns (r₁, r₀) such that:
      r ≡ r₁·α + r₀ (mod q)
      r₀ ∈ (-α/2, α/2]

    Special case: when r₁ = (q-1)/α, set r₁ = 0 and adjust r₀.
    """
    r = r % q

    # Compute r₀ = r mod α (centered around 0)
    r0 = r % alpha
    if r0 > alpha // 2:
        r0 -= alpha

    # Compute r₁ = (r - r₀) / α
    r1 = (r - r0) // alpha

    # Special case: prevent r₁ from reaching (q-1)/α
    m = (q - 1) // alpha
    if r1 == m:
        r1 = 0
        r0 = r0 - 1  # absorb the overflow

    return (r1, r0)


def high_bits(r: int, alpha: int, q: int) -> int:
    """Extract high-order bits: HighBits(r, α) = r₁ from Decompose."""
    r1, _ = decompose(r, alpha, q)
    return r1


def low_bits(r: int, alpha: int, q: int) -> int:
    """Extract low-order bits: LowBits(r, α) = r₀ from Decompose."""
    _, r0 = decompose(r, alpha, q)
    return r0


# ═══════════════════════════════════════════════════════════════
# Polynomial-level Decompose / HighBits / LowBits
# ═══════════════════════════════════════════════════════════════

def poly_decompose(
    p: Poly, alpha: int, q: int
) -> Tuple[Poly, Poly]:
    """Decompose each coefficient of a polynomial."""
    p1, p0 = [], []
    for c in p:
        r1, r0 = decompose(c, alpha, q)
        p1.append(r1)
        p0.append(r0)
    return p1, p0


def poly_high_bits(p: Poly, alpha: int, q: int) -> Poly:
    """HighBits for each coefficient of a polynomial."""
    return [high_bits(c, alpha, q) for c in p]


def poly_low_bits(p: Poly, alpha: int, q: int) -> Poly:
    """LowBits for each coefficient of a polynomial."""
    return [low_bits(c, alpha, q) for c in p]


# ═══════════════════════════════════════════════════════════════
# Vector-level HighBits / LowBits
# ═══════════════════════════════════════════════════════════════

def polyvec_high_bits(
    v: PolyVec, alpha: int, q: int
) -> PolyVec:
    """HighBits for each polynomial in a vector."""
    return [poly_high_bits(p, alpha, q) for p in v]


def polyvec_low_bits(
    v: PolyVec, alpha: int, q: int
) -> PolyVec:
    """LowBits for each polynomial in a vector."""
    return [poly_low_bits(p, alpha, q) for p in v]


def polyvec_low_bits_norm_inf(
    v: PolyVec, alpha: int, q: int
) -> int:
    """||LowBits(v)||∞ — max absolute value of any low-bits coefficient."""
    max_val = 0
    for p in v:
        for c in p:
            r0 = low_bits(c, alpha, q)
            max_val = max(max_val, abs(r0))
    return max_val


# ═══════════════════════════════════════════════════════════════
# Hint Functions: MakeHint / UseHint
# ═══════════════════════════════════════════════════════════════

def make_hint_coeff(z: int, r: int, alpha: int, q: int) -> int:
    """
    MakeHint for a single coefficient.

    Returns 1 if HighBits(r, α) ≠ HighBits(r + z, α), else 0.

    The hint tells the verifier whether the high bits changed
    due to the perturbation z (= -c·e in our ZKPoK).
    """
    r1 = high_bits(r, alpha, q)
    v1 = high_bits((r + z) % q, alpha, q)
    return 1 if r1 != v1 else 0


def use_hint_coeff(hint: int, r: int, alpha: int, q: int) -> int:
    """
    UseHint for a single coefficient.

    Given hint h and value r, recover the "correct" high bits.

    If h = 0: return HighBits(r) unchanged.
    If h = 1: adjust HighBits(r) by ±1 based on the sign of LowBits(r).
    """
    m = (q - 1) // alpha
    r1, r0 = decompose(r, alpha, q)

    if hint == 0:
        return r1
    else:
        if r0 > 0:
            return (r1 + 1) % m
        else:
            return (r1 - 1) % m


# ═══════════════════════════════════════════════════════════════
# Polynomial / Vector-level Hint Operations
# ═══════════════════════════════════════════════════════════════

def poly_make_hint(
    z: Poly, r: Poly, alpha: int, q: int
) -> List[int]:
    """MakeHint for each coefficient of two polynomials."""
    return [make_hint_coeff(z[i], r[i], alpha, q) for i in range(len(r))]


def poly_use_hint(
    hint: List[int], r: Poly, alpha: int, q: int
) -> Poly:
    """UseHint for each coefficient."""
    return [use_hint_coeff(hint[i], r[i], alpha, q) for i in range(len(r))]


def polyvec_make_hint(
    z_vec: PolyVec, r_vec: PolyVec,
    alpha: int, q: int
) -> List[List[int]]:
    """MakeHint for each polynomial in two vectors."""
    return [poly_make_hint(z_vec[i], r_vec[i], alpha, q)
            for i in range(len(r_vec))]


def polyvec_use_hint(
    hints: List[List[int]], r_vec: PolyVec,
    alpha: int, q: int
) -> PolyVec:
    """UseHint for each polynomial in a vector."""
    return [poly_use_hint(hints[i], r_vec[i], alpha, q)
            for i in range(len(r_vec))]


def count_hint_ones(hints: List[List[int]]) -> int:
    """Count total number of 1's across all hint polynomials."""
    return sum(sum(h) for h in hints)


# ═══════════════════════════════════════════════════════════════
# Hint Serialization
# ═══════════════════════════════════════════════════════════════

def encode_hints(hints: List[List[int]], omega: int, k: int) -> bytes:
    """
    Encode hints as a compact byte string.

    Format: For each polynomial, store the positions of 1-bits,
    followed by a sentinel. Total size ≤ ω + k bytes.
    """
    buf = bytearray()
    for poly_hint in hints:
        positions = [i for i, h in enumerate(poly_hint) if h == 1]
        for pos in positions:
            buf.append(pos & 0xFF)
    # Pad to fixed size
    while len(buf) < omega + k:
        buf.append(0)
    return bytes(buf[:omega + k])


def decode_hints(
    data: bytes, omega: int, k: int, n: int
) -> List[List[int]]:
    """Decode hints from compact byte string."""
    hints = []
    offset = 0
    for _ in range(k):
        poly_hint = [0] * n
        while offset < len(data) and data[offset] != 0:
            pos = data[offset]
            if pos < n:
                poly_hint[pos] = 1
            offset += 1
        offset += 1  # skip sentinel
        hints.append(poly_hint)
    return hints


# ═══════════════════════════════════════════════════════════════
# High-bits Serialization (for Fiat-Shamir hashing)
# ═══════════════════════════════════════════════════════════════

def encode_w1(w1: PolyVec, q: int, alpha: int) -> bytes:
    """
    Encode the high-bits vector w1 for hashing.

    Each high-bits value is in [0, (q-1)/α), encoded as 1 byte
    (sufficient since (q-1)/α = 88 < 256 for our parameters).
    """
    buf = bytearray()
    for poly in w1:
        for coeff in poly:
            buf.append(coeff & 0xFF)
    return bytes(buf)
