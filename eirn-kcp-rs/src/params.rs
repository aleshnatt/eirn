//! Lattice-Native ZKPoK Parameters.
//!
//! Adapted from CRYSTALS-Dilithium for the Eirn-KEM MLWE relation.
//! Uses `q = 8380417` (Dilithium's NTT-friendly prime) regardless of
//! the KEM modulus, with domain-separated matrix expansion.

/// Polynomial degree: ring R_q = Z_q[X]/(X^N + 1)
pub const N: usize = 256;

/// ZKPoK modulus (Dilithium's q, NTT-friendly: 2^23 - 2^13 + 1)
pub const Q: u32 = 8_380_417;

/// Half of q for centered representation
pub const Q_HALF: i32 = (Q as i32 - 1) / 2;

// ═══════════════════════════════════════════════════════════════
// Eirn-ZKP-512 Parameters (NIST Level 1)
// ═══════════════════════════════════════════════════════════════

/// Module rank (rows and columns of A_ZK)
pub const K_512: usize = 2;
pub const L_512: usize = 2;

/// Secret coefficient bound: |s_i|, |e_i| ≤ ETA
pub const ETA_512: u32 = 2;

/// Masking range: y_i ∈ [-GAMMA1+1, GAMMA1]
pub const GAMMA1_512: u32 = 1 << 17;  // 131072

/// Rounding parameter: (q-1)/88
pub const GAMMA2_512: u32 = 95_232;

/// Challenge weight: c has exactly TAU nonzero coefficients (each ±1)
pub const TAU_512: usize = 39;

/// Norm bound: β = τ·η
pub const BETA_512: u32 = TAU_512 as u32 * ETA_512;  // 78

/// Maximum hint weight
pub const OMEGA_512: usize = 80;

// ═══════════════════════════════════════════════════════════════
// Eirn-ZKP-768 Parameters (NIST Level 3)
// ═══════════════════════════════════════════════════════════════

pub const K_768: usize = 3;
pub const L_768: usize = 3;
pub const ETA_768: u32 = 2;
pub const GAMMA1_768: u32 = 1 << 19;  // 524288
pub const GAMMA2_768: u32 = 95_232;
pub const TAU_768: usize = 49;
pub const BETA_768: u32 = TAU_768 as u32 * ETA_768;  // 98
pub const OMEGA_768: usize = 96;

// ═══════════════════════════════════════════════════════════════
// Byte Sizes
// ═══════════════════════════════════════════════════════════════

/// Challenge hash size (SHA3-256 output)
pub const CHALLENGE_HASH_BYTES: usize = 32;

/// Seed size for matrix expansion
pub const SEED_BYTES: usize = 32;

/// Response vector size for ZKP-512: l × n × 3 bytes per coeff
pub const Z_BYTES_512: usize = L_512 * N * 3;  // 1536

/// Hint size for ZKP-512: ω + k bytes
pub const HINT_BYTES_512: usize = OMEGA_512 + K_512;  // 82

/// Total proof size for ZKP-512
pub const PROOF_BYTES_512: usize = CHALLENGE_HASH_BYTES + Z_BYTES_512 + HINT_BYTES_512;

/// Lattice public key size: 32 (rho) + k × n × 3 (t)
pub const LATTICE_PK_BYTES_512: usize = SEED_BYTES + K_512 * N * 3;

// ═══════════════════════════════════════════════════════════════
// Domain Separation Labels
// ═══════════════════════════════════════════════════════════════

/// Matrix expansion domain separator
pub const MATRIX_DOMAIN: &[u8] = b"eirn-zk-matrix-v1";

/// Fiat-Shamir challenge domain separator
pub const CHALLENGE_DOMAIN: &[u8] = b"eirn-zk-challenge-v1";

/// Key split domain separators
pub const KEYSPLIT_RHO_DOMAIN: &[u8] = b"eirn-zk-keysplit-rho";
pub const KEYSPLIT_SIGMA_DOMAIN: &[u8] = b"eirn-zk-keysplit-sigma";

/// Ratchet KDF domain separator
pub const RATCHET_KDF_DOMAIN: &[u8] = b"eirn-ratchet-kdf";
