//! Updated Message Structures for Eirn-KCP v2.0.
//!
//! Defines MSG₀' with cipher suite negotiation supporting
//! both KCP-Lite (96B) and KCP-Strict (~1.3KB) modes.

use crate::params::*;
use crate::zkp::{KcpMode, KcpProof, LatticeZkProof, KcpLiteProof};

// ═══════════════════════════════════════════════════════════════
// KEM Key / Ciphertext Sizes (Eirn-512)
// ═══════════════════════════════════════════════════════════════

const PK_BYTES: usize = 800;       // Eirn-512 public key
const SK_BYTES: usize = 32;        // Eirn-512 secret key seed
const CT_BYTES: usize = 768;       // Eirn-512 ciphertext

// ═══════════════════════════════════════════════════════════════
// MSG₀' — Extended Initial Handshake Message
// ═══════════════════════════════════════════════════════════════

/// Extended initial handshake message with KCP proof.
///
/// ```text
/// MSG₀' = Header || pk_A || ek_A || ct1 || ct2 || ct3 || ct4 || KcpPayload
///
/// Header (2 bytes):
///   version: u8      — Protocol version (0x02 for v2.0)
///   kcp_mode: u8     — KCP mode (0x00 = Lite, 0x01 = Strict)
///
/// KcpPayload:
///   If Lite:   π_KCP  (96 bytes)
///   If Strict: pk_ZK  (rho || t) + π_ZK  (~1,266 bytes proof + 1,568 pk)
/// ```
pub struct Msg0Prime {
    /// Protocol version.
    pub version: u8,
    /// KCP mode for this message.
    pub kcp_mode: KcpMode,
    /// Sender's identity public key.
    pub pk_a: [u8; PK_BYTES],
    /// Sender's ephemeral public key.
    pub ek_a: [u8; PK_BYTES],
    /// KEM ciphertext to pk_B (identity binding).
    pub ct1: [u8; CT_BYTES],
    /// KEM ciphertext to spk_B (prekey FS).
    pub ct2: [u8; CT_BYTES],
    /// KEM ciphertext to opk_B (one-time FS).
    pub ct3: [u8; CT_BYTES],
    /// NAXOS-KEM ciphertext (authentication).
    pub ct4: [u8; CT_BYTES],
    /// KCP proof (mode-dependent size).
    pub kcp_proof: KcpProof,
    /// Lattice public key (only present in Strict mode).
    pub lattice_pk_rho: Option<[u8; SEED_BYTES]>,
    pub lattice_pk_t: Option<Vec<u8>>,
}

impl Msg0Prime {
    /// Protocol version for v2.0.
    pub const VERSION: u8 = 0x02;

    /// Total message size in bytes.
    pub fn total_size(&self) -> usize {
        let base = 2  // header
            + PK_BYTES * 2  // pk_A + ek_A
            + CT_BYTES * 4; // ct1..ct4

        let proof_size = self.kcp_proof.size();

        let lattice_pk_size = match self.kcp_mode {
            KcpMode::Strict => LATTICE_PK_BYTES_512,
            KcpMode::Lite => 0,
        };

        base + proof_size + lattice_pk_size
    }
}

// ═══════════════════════════════════════════════════════════════
// Size Summary
// ═══════════════════════════════════════════════════════════════

/// ```text
/// ┌─────────────────┬────────────┬────────────┐
/// │ Component       │ Lite (v1)  │ Strict (v2)│
/// ├─────────────────┼────────────┼────────────┤
/// │ Header          │   2 B      │   2 B      │
/// │ pk_A            │ 800 B      │ 800 B      │
/// │ ek_A            │ 800 B      │ 800 B      │
/// │ ct1..ct4        │ 3072 B     │ 3072 B     │
/// │ lattice_pk      │   0 B      │ 1568 B     │
/// │ KCP proof       │  96 B      │ 1650 B     │
/// ├─────────────────┼────────────┼────────────┤
/// │ TOTAL MSG₀'     │ 4770 B     │ 7892 B     │
/// │ (real MLWE)     │ ~6.2 KB    │ ~9.1 KB    │
/// └─────────────────┴────────────┴────────────┘
/// ```
pub const MSG0_SIZE_LITE: usize = 2 + PK_BYTES * 2 + CT_BYTES * 4 + KcpLiteProof::SIZE;
pub const MSG0_SIZE_STRICT: usize = 2 + PK_BYTES * 2 + CT_BYTES * 4
    + LATTICE_PK_BYTES_512 + LatticeZkProof::SIZE;
