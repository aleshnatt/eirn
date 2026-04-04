//! Lattice-Native ZKPoK: Prove and Verify.
//!
//! Implements the Lyubashevsky rejection-sampling Σ-protocol over the
//! MLWE key derivation relation for Eirn-KEM.
//!
//! ## Protocol Overview
//!
//! ```text
//! Relation: { (A, t), (s, e) | t = A·s + e mod q, ||s||∞,||e||∞ ≤ η }
//!
//! Prove(s, e, A, t, ctx):
//!   1. y ← S_γ₁^l                       (masking vector)
//!   2. w = A·y mod q                      (commitment)
//!   3. w₁ = HighBits(w, 2γ₂)
//!   4. c̃ = H(w₁ ‖ t ‖ ctx)             (Fiat-Shamir)
//!   5. c = SampleInBall(c̃, τ)
//!   6. z = y + c·s                        (response)
//!   7. Reject if ||z||∞ ≥ γ₁ - β
//!   8. Reject if ||LowBits(Az-ct)||∞ ≥ γ₂ - β
//!   9. h = MakeHint(-c·e, w, 2γ₂)
//!   10. Output π = (c̃, z, h)
//!
//! Verify(A, t, ctx, π):
//!   1. Check ||z||∞ < γ₁ - β
//!   2. c = SampleInBall(c̃, τ)
//!   3. r = A·z - c·t
//!   4. w₁' = UseHint(h, r, 2γ₂)
//!   5. Check c̃ == H(w₁' ‖ t ‖ ctx)
//! ```

use crate::params::*;
use crate::poly::*;

// ═══════════════════════════════════════════════════════════════
// KCP Mode Selection
// ═══════════════════════════════════════════════════════════════

/// KCP cipher suite mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KcpMode {
    /// 96-byte hash-based KCP (v1.1 — wrong-key soundness only).
    Lite = 0x00,
    /// ~1.3 KB Lattice-native ZKPoK (full PoK extractability).
    Strict = 0x01,
}

// ═══════════════════════════════════════════════════════════════
// Key Types
// ═══════════════════════════════════════════════════════════════

/// Lattice public key for the ZKPoK.
///
/// Contains the matrix expansion seed and public vector t.
/// Sent alongside the identity public key during handshake.
#[derive(Clone)]
pub struct LatticePublicKey {
    /// 32-byte seed for A_ZK expansion.
    pub rho: [u8; SEED_BYTES],
    /// Public vector t = A·s + e ∈ R_q^K.
    pub t: PolyVec<2>,  // K_512 = 2
}

/// Lattice secret key for the ZKPoK.
///
/// Contains the MLWE secret and error vectors.
/// MUST be zeroized after use in production.
pub struct LatticeSecretKey {
    /// Secret vector s ∈ R_q^L (coeffs in [-η, η]).
    pub s: PolyVec<2>,  // L_512 = 2
    /// Error vector e ∈ R_q^K (coeffs in [-η, η]).
    pub e: PolyVec<2>,  // K_512 = 2
    /// Matrix seed (cached for convenience).
    pub rho: [u8; SEED_BYTES],
    /// Public vector (cached for convenience).
    pub t: PolyVec<2>,
}

// ═══════════════════════════════════════════════════════════════
// Proof Structure
// ═══════════════════════════════════════════════════════════════

/// Lattice-native Zero-Knowledge Proof of Knowledge.
///
/// Total size: CHALLENGE_HASH_BYTES + Z_BYTES + HINT_BYTES
///           = 32 + 1536 + 82 = 1650 bytes (ZKP-512)
#[derive(Clone)]
pub struct LatticeZkProof {
    /// Fiat-Shamir challenge hash c̃ (32 bytes).
    pub c_hash: [u8; CHALLENGE_HASH_BYTES],
    /// Response vector z ∈ R_q^L (serialized).
    pub z_bytes: [u8; Z_BYTES_512],
    /// Verification hints h (serialized).
    pub h_bytes: [u8; HINT_BYTES_512],
}

impl LatticeZkProof {
    /// Total proof size in bytes.
    pub const SIZE: usize = PROOF_BYTES_512;

    /// Serialize to contiguous byte buffer.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..CHALLENGE_HASH_BYTES].copy_from_slice(&self.c_hash);
        buf[CHALLENGE_HASH_BYTES..CHALLENGE_HASH_BYTES + Z_BYTES_512]
            .copy_from_slice(&self.z_bytes);
        buf[CHALLENGE_HASH_BYTES + Z_BYTES_512..]
            .copy_from_slice(&self.h_bytes);
        buf
    }

    /// Deserialize from byte buffer.
    pub fn from_bytes(data: &[u8; Self::SIZE]) -> Self {
        let mut c_hash = [0u8; CHALLENGE_HASH_BYTES];
        let mut z_bytes = [0u8; Z_BYTES_512];
        let mut h_bytes = [0u8; HINT_BYTES_512];

        c_hash.copy_from_slice(&data[..CHALLENGE_HASH_BYTES]);
        z_bytes.copy_from_slice(
            &data[CHALLENGE_HASH_BYTES..CHALLENGE_HASH_BYTES + Z_BYTES_512],
        );
        h_bytes.copy_from_slice(&data[CHALLENGE_HASH_BYTES + Z_BYTES_512..]);

        LatticeZkProof { c_hash, z_bytes, h_bytes }
    }
}

// ═══════════════════════════════════════════════════════════════
// KCP-Lite Proof (hash-based, 96 bytes)
// ═══════════════════════════════════════════════════════════════

/// Hash-based Key Consistency Proof (v1.1 compatible).
///
/// 96 bytes: commitment (32) + response (32) + anchor (32).
#[derive(Clone)]
pub struct KcpLiteProof {
    pub commitment: [u8; 32],
    pub response: [u8; 32],
    pub anchor: [u8; 32],
}

impl KcpLiteProof {
    pub const SIZE: usize = 96;
}

// ═══════════════════════════════════════════════════════════════
// Unified Proof Enum
// ═══════════════════════════════════════════════════════════════

/// Unified proof type supporting both KCP modes.
#[derive(Clone)]
pub enum KcpProof {
    Lite(KcpLiteProof),
    Strict(LatticeZkProof),
}

impl KcpProof {
    /// Proof size in bytes.
    pub fn size(&self) -> usize {
        match self {
            KcpProof::Lite(_) => KcpLiteProof::SIZE,
            KcpProof::Strict(_) => LatticeZkProof::SIZE,
        }
    }

    /// Mode of this proof.
    pub fn mode(&self) -> KcpMode {
        match self {
            KcpProof::Lite(_) => KcpMode::Lite,
            KcpProof::Strict(_) => KcpMode::Strict,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Function Signatures (Stubs)
// ═══════════════════════════════════════════════════════════════

/// Derive lattice key pair from KEM seed.
///
/// Generates (A_ZK, s, e, t) from the 32-byte KEM secret key seed
/// using domain-separated key splitting.
pub fn derive_lattice_keys(
    _kem_seed: &[u8; 32],
) -> (LatticePublicKey, LatticeSecretKey) {
    // TODO: Implement key derivation
    // 1. rho = SHA3-256(kem_seed || KEYSPLIT_RHO_DOMAIN)
    // 2. sigma = SHA3-256(kem_seed || KEYSPLIT_SIGMA_DOMAIN)
    // 3. A = ExpandA(SHA3-256(rho || MATRIX_DOMAIN))
    // 4. s = CBD_η(sigma, nonce=0..L-1)
    // 5. e = CBD_η(sigma, nonce=L..L+K-1)
    // 6. t = A·s + e mod q
    unimplemented!()
}

/// Generate a lattice-native ZKPoK.
///
/// Proves knowledge of s such that t = A·s + e mod q.
///
/// Expected to succeed within ~4 rejection sampling iterations.
/// Returns `None` if `max_attempts` is exceeded.
pub fn lattice_prove(
    _sk: &LatticeSecretKey,
    _ctx: &[u8],
    _max_attempts: u32,
) -> Option<LatticeZkProof> {
    // TODO: Implement Lyubashevsky Σ-protocol
    // 1. Expand A from sk.rho
    // 2. Loop (rejection sampling):
    //    a. y ← S_γ₁^l
    //    b. w = A·y
    //    c. w₁ = HighBits(w, 2γ₂)
    //    d. c̃ = SHA3-256(CHALLENGE_DOMAIN || w₁ || t || ctx)
    //    e. c = SampleInBall(c̃)
    //    f. z = y + c·s
    //    g. Check norms, compute hints
    // 3. Return (c̃, z, h)
    unimplemented!()
}

/// Verify a lattice-native ZKPoK.
///
/// Verifies in fail-fast order:
///   1. Hint weight ≤ ω
///   2. ||z||∞ < γ₁ - β
///   3. c = SampleInBall(c̃)
///   4. r = A·z - c·t
///   5. w₁' = UseHint(h, r)
///   6. c̃ == H(w₁' || t || ctx)
pub fn lattice_verify(
    _pk: &LatticePublicKey,
    _ctx: &[u8],
    _proof: &LatticeZkProof,
) -> bool {
    // TODO: Implement verification
    unimplemented!()
}

/// Generate a KCP-Lite proof (hash-based, 96 bytes).
pub fn kcp_lite_prove(
    _sk_seed: &[u8; 32],
    _pk: &[u8; 32],
    _ctx: &[u8],
) -> KcpLiteProof {
    // TODO: Port from Python zk/sigma.py
    unimplemented!()
}

/// Verify a KCP-Lite proof.
pub fn kcp_lite_verify(
    _pk: &[u8; 32],
    _ctx: &[u8],
    _proof: &KcpLiteProof,
) -> bool {
    // TODO: Port from Python zk/sigma.py
    unimplemented!()
}
