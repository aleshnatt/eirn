"""
Polynomial Arithmetic over R_q = Z_q[X]/(X^n + 1).

Implements coefficient-level operations for the lattice-native ZKPoK.
Uses schoolbook multiplication (O(n²)) for the research prototype.
A production implementation would use NTT-based O(n log n) multiplication.

All polynomials are represented as lists of n integers in [0, q).
Module vectors are lists of polynomials.
Module matrices are lists of lists of polynomials (row-major).
"""

from typing import List
from .params import LatticeZKParams, DEFAULT_ZK_PARAMS

# Type aliases for clarity
Poly = List[int]            # Single polynomial: n coefficients in [0, q)
PolyVec = List[Poly]        # Vector of polynomials (length k or l)
PolyMat = List[PolyVec]     # Matrix of polynomials (k × l)


# ═══════════════════════════════════════════════════════════════
# Scalar / Coefficient Operations
# ═══════════════════════════════════════════════════════════════

def mod_centered(x: int, q: int) -> int:
    """Map x ∈ Z_q to centered representation in [-(q-1)/2, (q-1)/2]."""
    r = x % q
    if r > q // 2:
        r -= q
    return r


def coeff_norm_inf(coeffs: List[int], q: int) -> int:
    """Compute ||coeffs||∞ in centered representation."""
    return max(abs(mod_centered(c, q)) for c in coeffs)


# ═══════════════════════════════════════════════════════════════
# Polynomial Operations in R_q = Z_q[X]/(X^n + 1)
# ═══════════════════════════════════════════════════════════════

def poly_zero(n: int) -> Poly:
    """Return the zero polynomial."""
    return [0] * n


def poly_add(a: Poly, b: Poly, q: int) -> Poly:
    """Polynomial addition: (a + b) mod q."""
    return [(a[i] + b[i]) % q for i in range(len(a))]


def poly_sub(a: Poly, b: Poly, q: int) -> Poly:
    """Polynomial subtraction: (a - b) mod q."""
    return [(a[i] - b[i]) % q for i in range(len(a))]


def poly_neg(a: Poly, q: int) -> Poly:
    """Polynomial negation: (-a) mod q."""
    return [(-c) % q for c in a]


def poly_mul(a: Poly, b: Poly, q: int, n: int) -> Poly:
    """
    Polynomial multiplication in R_q = Z_q[X]/(X^n + 1).

    Schoolbook algorithm with reduction mod (X^n + 1).
    Uses the identity: X^n ≡ -1 (mod X^n + 1).

    Complexity: O(n²). Production code would use NTT.
    """
    c = [0] * n
    for i in range(n):
        if a[i] == 0:
            continue
        for j in range(n):
            if b[j] == 0:
                continue
            idx = i + j
            prod = a[i] * b[j]
            if idx < n:
                c[idx] = (c[idx] + prod) % q
            else:
                # X^(n+r) = X^r · X^n ≡ -X^r (mod X^n + 1)
                c[idx - n] = (c[idx - n] - prod) % q
    return c


def poly_scale(a: Poly, scalar: int, q: int) -> Poly:
    """Scalar multiplication: scalar · a mod q."""
    return [(scalar * c) % q for c in a]


def poly_norm_inf(a: Poly, q: int) -> int:
    """Infinity norm of polynomial in centered representation."""
    return coeff_norm_inf(a, q)


# ═══════════════════════════════════════════════════════════════
# Module Vector Operations
# ═══════════════════════════════════════════════════════════════

def polyvec_add(a: PolyVec, b: PolyVec, q: int) -> PolyVec:
    """Component-wise vector addition."""
    return [poly_add(a[i], b[i], q) for i in range(len(a))]


def polyvec_sub(a: PolyVec, b: PolyVec, q: int) -> PolyVec:
    """Component-wise vector subtraction."""
    return [poly_sub(a[i], b[i], q) for i in range(len(a))]


def polyvec_neg(a: PolyVec, q: int) -> PolyVec:
    """Component-wise negation."""
    return [poly_neg(p, q) for p in a]


def polyvec_norm_inf(v: PolyVec, q: int) -> int:
    """Infinity norm of a polynomial vector (max over all coefficients)."""
    return max(poly_norm_inf(p, q) for p in v)


# ═══════════════════════════════════════════════════════════════
# Matrix-Vector Multiplication
# ═══════════════════════════════════════════════════════════════

def matvec_mul(A: PolyMat, v: PolyVec, q: int, n: int) -> PolyVec:
    """
    Matrix-vector multiplication: w = A · v in R_q^k.

    A is k×l, v is length l, result is length k.
    Each entry is a polynomial in R_q.
    """
    k = len(A)
    l = len(A[0])
    assert len(v) == l, f"Dimension mismatch: A is {k}×{l}, v is {len(v)}"

    result = [poly_zero(n) for _ in range(k)]
    for i in range(k):
        for j in range(l):
            prod = poly_mul(A[i][j], v[j], q, n)
            result[i] = poly_add(result[i], prod, q)
    return result


def polyvec_inner(a: PolyVec, b: PolyVec, q: int, n: int) -> Poly:
    """Inner product of two polynomial vectors: <a, b> = Σ a_i · b_i."""
    assert len(a) == len(b)
    result = poly_zero(n)
    for i in range(len(a)):
        prod = poly_mul(a[i], b[i], q, n)
        result = poly_add(result, prod, q)
    return result


# ═══════════════════════════════════════════════════════════════
# Serialization (for hashing / proof encoding)
# ═══════════════════════════════════════════════════════════════

def poly_to_bytes(p: Poly, q: int) -> bytes:
    """
    Serialize polynomial coefficients to bytes.

    Each coefficient is encoded as 3 bytes (24 bits) in little-endian,
    sufficient for q = 8380417 < 2^23.
    """
    buf = bytearray()
    for c in p:
        val = c % q  # ensure positive
        buf.append(val & 0xFF)
        buf.append((val >> 8) & 0xFF)
        buf.append((val >> 16) & 0xFF)
    return bytes(buf)


def poly_from_bytes(data: bytes, n: int, q: int) -> Poly:
    """Deserialize polynomial from bytes (3 bytes per coefficient)."""
    assert len(data) == n * 3
    p = []
    for i in range(n):
        val = data[3*i] | (data[3*i+1] << 8) | (data[3*i+2] << 16)
        p.append(val % q)
    return p


def polyvec_to_bytes(v: PolyVec, q: int) -> bytes:
    """Serialize a polynomial vector."""
    return b"".join(poly_to_bytes(p, q) for p in v)


def polyvec_from_bytes(data: bytes, dim: int, n: int, q: int) -> PolyVec:
    """Deserialize a polynomial vector."""
    poly_size = n * 3
    assert len(data) == dim * poly_size
    return [poly_from_bytes(data[i*poly_size:(i+1)*poly_size], n, q)
            for i in range(dim)]


def encode_z(z: PolyVec, gamma1: int, n: int, q: int) -> bytes:
    """
    Encode response vector z with coefficients in [-γ₁+1, γ₁].
    """
    buf = bytearray()
    for poly in z:
        for coeff in poly:
            # First map to centered representation (if it was [0, q))
            c_centered = mod_centered(coeff, q)
            # Shift to positive: val = γ₁ - c_centered
            val = gamma1 - c_centered
            buf.extend(val.to_bytes(3, 'little', signed=False))
    return bytes(buf)


def decode_z(data: bytes, dim: int, n: int, gamma1: int) -> PolyVec:
    """Decode response vector z from bytes."""
    z = []
    offset = 0
    for _ in range(dim):
        poly = []
        for _ in range(n):
            val = int.from_bytes(data[offset:offset+3], 'little')
            coeff = gamma1 - val
            poly.append(coeff)
            offset += 3
        z.append(poly)
    return z
