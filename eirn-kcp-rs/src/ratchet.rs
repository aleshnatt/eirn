//! Eirn-Ratchet: Message Structures and State.
//!
//! Extends the KCP layer to provide continuous identity binding
//! during KEM-based ratchet key rotations.

use crate::params::*;
use crate::zkp::{KcpMode, KcpProof, LatticePublicKey};

const PK_BYTES: usize = 800; // Eirn-512 public key
const CT_BYTES: usize = 768; // Eirn-512 ciphertext

// ═══════════════════════════════════════════════════════════════
// Ratchet Message
// ═══════════════════════════════════════════════════════════════

/// Message sent during a ratchet key rotation.
///
/// Contains the new ephemeral key, a ciphertext encapsulated to the
/// peer's current ephemeral key, and a ZK proof binding the new key
/// to the sender's long-term identity.
pub struct RatchetMessage {
    /// New ephemeral public key (sender's fresh key).
    pub ek_new: [u8; PK_BYTES],
    /// KEM ciphertext to peer's last ek.
    pub ct_ratchet: [u8; CT_BYTES],
    /// Ratchet epoch counter.
    pub epoch: u32,
    /// Which proof mode is used for this ratchet step.
    pub kcp_mode: KcpMode,
    /// ZK proof binding `ek_new` to the sender's long-term identity.
    /// Context: c̃_ratchet = H(pk_identity || ek_prev || ek_new || epoch)
    pub zk_proof: KcpProof,
}

impl RatchetMessage {
    /// Compute total serialized message size.
    pub fn total_size(&self) -> usize {
        PK_BYTES + CT_BYTES + 4 + 1 /* mode byte */ + self.zk_proof.size()
    }
}

// ═══════════════════════════════════════════════════════════════
// Ratchet State (Stub)
// ═══════════════════════════════════════════════════════════════

/// Participant state for the Eirn-Ratchet protocol.
pub struct RatchetState {
    /// Current symmetric chain key.
    pub chain_key: [u8; 32],
    /// Current epoch counter.
    pub epoch: u32,
    /// Our current ephemeral public key.
    pub ek_self: [u8; PK_BYTES],
    /// Peer's current ephemeral public key.
    pub ek_peer: [u8; PK_BYTES],
    /// The cipher suite mode selected for the session.
    pub kcp_mode: KcpMode,
}
