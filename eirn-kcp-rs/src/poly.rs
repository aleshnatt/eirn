//! Polynomial Types and NTT Stubs for R_q = Z_q[X]/(X^256 + 1).
//!
//! Provides the foundational types for lattice arithmetic.
//! NTT implementation is stubbed — a production build would use
//! optimized NTT from the Dilithium reference implementation.

use crate::params::{N, Q};

// ═══════════════════════════════════════════════════════════════
// Core Polynomial Type
// ═══════════════════════════════════════════════════════════════

/// A polynomial in R_q = Z_q[X]/(X^256 + 1).
///
/// Coefficients stored in standard (non-NTT) representation,
/// each in [0, Q). Centered representation uses [-Q/2, Q/2].
#[derive(Clone, Debug)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Poly {
    /// Zero polynomial.
    pub const fn zero() -> Self {
        Poly { coeffs: [0i32; N] }
    }

    /// Reduce all coefficients mod Q to [0, Q).
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = ((*c % Q as i32) + Q as i32) as i32 % Q as i32;
        }
    }

    /// Infinity norm in centered representation.
    pub fn norm_inf(&self) -> u32 {
        self.coeffs.iter()
            .map(|&c| {
                let r = c.rem_euclid(Q as i32);
                if r > Q as i32 / 2 { Q as i32 - r } else { r }
            })
            .max()
            .unwrap_or(0) as u32
    }

    /// Polynomial addition: (self + other) mod Q.
    pub fn add(&self, other: &Poly) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            result.coeffs[i] = (self.coeffs[i] + other.coeffs[i]).rem_euclid(Q as i32);
        }
        result
    }

    /// Polynomial subtraction: (self - other) mod Q.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            result.coeffs[i] = (self.coeffs[i] - other.coeffs[i]).rem_euclid(Q as i32);
        }
        result
    }

    /// Schoolbook multiplication in R_q = Z_q[X]/(X^N + 1).
    ///
    /// O(N²) — production code should use NTT-based multiplication.
    pub fn mul(&self, other: &Poly) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            if self.coeffs[i] == 0 { continue; }
            for j in 0..N {
                if other.coeffs[j] == 0 { continue; }
                let prod = (self.coeffs[i] as i64) * (other.coeffs[j] as i64);
                let idx = i + j;
                if idx < N {
                    result.coeffs[idx] = ((result.coeffs[idx] as i64 + prod) % Q as i64) as i32;
                } else {
                    // X^N ≡ -1 mod (X^N + 1)
                    result.coeffs[idx - N] = ((result.coeffs[idx - N] as i64 - prod) % Q as i64) as i32;
                }
            }
        }
        result.reduce();
        result
    }

    /// NTT forward transform (STUB — to be implemented).
    pub fn ntt(&mut self) {
        // TODO: Implement NTT for q = 8380417
        // Uses primitive 512th root of unity: ζ = 1753
        unimplemented!("NTT forward transform")
    }

    /// NTT inverse transform (STUB — to be implemented).
    pub fn inv_ntt(&mut self) {
        unimplemented!("NTT inverse transform")
    }

    /// Serialize to bytes (3 bytes per coefficient, little-endian).
    pub fn to_bytes(&self) -> [u8; N * 3] {
        let mut buf = [0u8; N * 3];
        for i in 0..N {
            let val = self.coeffs[i].rem_euclid(Q as i32) as u32;
            buf[3 * i] = (val & 0xFF) as u8;
            buf[3 * i + 1] = ((val >> 8) & 0xFF) as u8;
            buf[3 * i + 2] = ((val >> 16) & 0xFF) as u8;
        }
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8; N * 3]) -> Self {
        let mut p = Poly::zero();
        for i in 0..N {
            let val = data[3 * i] as u32
                | ((data[3 * i + 1] as u32) << 8)
                | ((data[3 * i + 2] as u32) << 16);
            p.coeffs[i] = (val % Q) as i32;
        }
        p
    }
}

// ═══════════════════════════════════════════════════════════════
// Polynomial Vector (Module Element)
// ═══════════════════════════════════════════════════════════════

/// A vector of polynomials in R_q^k.
#[derive(Clone, Debug)]
pub struct PolyVec<const DIM: usize> {
    pub polys: [Poly; DIM],
}

impl<const DIM: usize> PolyVec<DIM> {
    /// Zero vector.
    pub fn zero() -> Self {
        PolyVec {
            polys: core::array::from_fn(|_| Poly::zero()),
        }
    }

    /// Component-wise addition.
    pub fn add(&self, other: &Self) -> Self {
        PolyVec {
            polys: core::array::from_fn(|i| self.polys[i].add(&other.polys[i])),
        }
    }

    /// Component-wise subtraction.
    pub fn sub(&self, other: &Self) -> Self {
        PolyVec {
            polys: core::array::from_fn(|i| self.polys[i].sub(&other.polys[i])),
        }
    }

    /// Infinity norm (max over all polynomial norms).
    pub fn norm_inf(&self) -> u32 {
        self.polys.iter().map(|p| p.norm_inf()).max().unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════════
// Matrix-Vector Multiplication
// ═══════════════════════════════════════════════════════════════

/// Matrix A ∈ R_q^{K×L} represented as K rows of L polynomials.
#[derive(Clone, Debug)]
pub struct PolyMat<const K: usize, const L: usize> {
    pub rows: [PolyVec<L>; K],
}

impl<const K: usize, const L: usize> PolyMat<K, L> {
    /// Matrix-vector multiplication: A · v ∈ R_q^K.
    pub fn mul_vec(&self, v: &PolyVec<L>) -> PolyVec<K> {
        PolyVec {
            polys: core::array::from_fn(|i| {
                let mut acc = Poly::zero();
                for j in 0..L {
                    let prod = self.rows[i].polys[j].mul(&v.polys[j]);
                    acc = acc.add(&prod);
                }
                acc
            }),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Rounding (Decompose / HighBits / LowBits)
// ═══════════════════════════════════════════════════════════════

/// Decompose r into (high, low) parts: r = r₁·α + r₀.
pub fn decompose(r: i32, alpha: u32) -> (i32, i32) {
    let r_pos = r.rem_euclid(Q as i32);
    let mut r0 = r_pos % alpha as i32;
    if r0 > alpha as i32 / 2 {
        r0 -= alpha as i32;
    }
    let mut r1 = (r_pos - r0) / alpha as i32;

    let m = (Q - 1) / alpha;
    if r1 == m as i32 {
        r1 = 0;
        r0 -= 1;
    }
    (r1, r0)
}

/// Extract high-order bits.
pub fn high_bits(r: i32, alpha: u32) -> i32 {
    decompose(r, alpha).0
}

/// Extract low-order bits.
pub fn low_bits(r: i32, alpha: u32) -> i32 {
    decompose(r, alpha).1
}

/// MakeHint: returns 1 if HighBits(r) ≠ HighBits(r + z).
pub fn make_hint(z: i32, r: i32, alpha: u32) -> u8 {
    let r1 = high_bits(r, alpha);
    let v1 = high_bits((r + z).rem_euclid(Q as i32), alpha);
    if r1 != v1 { 1 } else { 0 }
}

/// UseHint: adjust HighBits based on hint.
pub fn use_hint(hint: u8, r: i32, alpha: u32) -> i32 {
    let m = ((Q - 1) / alpha) as i32;
    let (r1, r0) = decompose(r, alpha);
    if hint == 0 {
        r1
    } else if r0 > 0 {
        (r1 + 1).rem_euclid(m)
    } else {
        (r1 - 1).rem_euclid(m)
    }
}
