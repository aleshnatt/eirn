//! KCP-Lite key consistency proofs.
//!
//! This module implements a signature-backed consistency proof for the current
//! Eirn-KCP handshake mode. It is designed to bind a sender public key to a
//! session context under an Ed25519 signing key. It is not a formal
//! zero-knowledge proof system, and strict lattice-native KCP is reserved but
//! not implemented in this crate version.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{
    error::{EirnError, Result},
    kem::{PublicKey, SecretKey},
    util::{ct_eq, sha3_256},
};

const KCP_LITE_SIGN_LABEL: &[u8] = b"eirn-kcp-lite-sign-v1";
const KCP_LITE_ANCHOR_LABEL: &[u8] = b"eirn-kcp-lite-anchor-v1";

/// Handshake key consistency mode.
///
/// The mode byte selects the proof system encoded in `MSG0'`. Only `Lite`
/// currently has verification semantics in this crate. Callers must reject
/// unsupported modes rather than silently downgrading or interpreting them as
/// `Lite`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KcpMode {
    /// Hash-based KCP-Lite mode. This is the only handshake mode implemented
    /// in the current crate version.
    Lite = 0x00,
    /// Reserved for a future lattice-native strict proof mode.
    ///
    /// Current APIs reject this mode with [`EirnError::StrictModeUnavailable`].
    Strict = 0x01,
}

/// A lightweight key consistency proof for Eirn-KCP.
///
/// The proof is an Ed25519 signature over the session context plus an anchor
/// hash binding the encoded proof. It carries proof of possession of the sender
/// secret key for the supplied context, not anonymity or witness hiding. Callers
/// must ensure the context is session-unique and contains the intended peer
/// identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KcpLiteProof {
    pub commitment: [u8; 32],
    pub response: [u8; 64],
    pub anchor: [u8; 32],
}

impl KcpLiteProof {
    /// Fixed encoded KCP-Lite proof size in bytes.
    pub const SIZE: usize = 128;

    /// Serializes the proof to its fixed-size wire encoding.
    ///
    /// # Security
    ///
    /// Serialization preserves proof bytes but does not validate them. Callers
    /// must run [`kcp_lite_verify`] before accepting a decoded or received
    /// proof.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..32].copy_from_slice(&self.commitment);
        out[32..96].copy_from_slice(&self.response);
        out[96..].copy_from_slice(&self.anchor);
        out
    }

    /// Parses a proof from its fixed-size wire encoding.
    ///
    /// # Errors
    ///
    /// Returns [`EirnError::InvalidProofLength`] if `data` is not exactly
    /// [`KcpLiteProof::SIZE`] bytes.
    ///
    /// # Untrusted Input
    ///
    /// This function accepts data from untrusted sources. All structural checks
    /// are performed before any arithmetic. Malformed input is rejected with an
    /// error rather than panicking.
    ///
    /// # Security
    ///
    /// Parsing does not verify the signature or anchor. Callers must verify the
    /// returned proof against the expected public key and context.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SIZE {
            return Err(EirnError::InvalidProofLength {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }
        let mut commitment = [0u8; 32];
        let mut response = [0u8; 64];
        let mut anchor = [0u8; 32];
        commitment.copy_from_slice(&data[..32]);
        response.copy_from_slice(&data[32..96]);
        anchor.copy_from_slice(&data[96..]);
        Ok(Self {
            commitment,
            response,
            anchor,
        })
    }
}

/// Creates a KCP-Lite proof for `pk` and `ctx`.
///
/// # Errors
///
/// Returns [`EirnError::KeyMismatch`] if `sk` does not derive the supplied
/// public-key bytes.
///
/// # Security
///
/// `ctx` must be session-unique and must include the intended receiver identity
/// and sender ephemeral key. This function signs the context; it does not hide
/// the sender public key.
pub fn kcp_lite_prove(sk: &SecretKey, pk: &[u8; 32], ctx: &[u8]) -> Result<KcpLiteProof> {
    let sk_seed = sk.seed();
    let signing_key = SigningKey::from_bytes(sk_seed);
    let commitment = signing_key.verifying_key().to_bytes();
    if !ct_eq(&commitment, pk) {
        return Err(EirnError::KeyMismatch);
    }

    let message = proof_message(&commitment, ctx);
    let response = signing_key.sign(&message).to_bytes();

    let mut bind_input = Vec::with_capacity(KCP_LITE_ANCHOR_LABEL.len() + 32 + 64 + ctx.len());
    bind_input.extend_from_slice(KCP_LITE_ANCHOR_LABEL);
    bind_input.extend_from_slice(&commitment);
    bind_input.extend_from_slice(&response);
    bind_input.extend_from_slice(ctx);
    let anchor = sha3_256(&bind_input);

    Ok(KcpLiteProof {
        commitment,
        response,
        anchor,
    })
}

/// Creates a KCP-Lite proof using a typed public key.
///
/// # Errors
///
/// Returns [`EirnError::KeyMismatch`] if `sk` does not own `pk`.
///
/// # Security
///
/// `ctx` must be session-unique and must include the intended receiver identity
/// and sender ephemeral key. Prefer this typed helper over raw byte proofs when
/// the caller has a [`PublicKey`] value.
pub fn kcp_lite_prove_for_key(sk: &SecretKey, pk: &PublicKey, ctx: &[u8]) -> Result<KcpLiteProof> {
    if !sk.matches_public_key(pk) {
        return Err(EirnError::KeyMismatch);
    }
    kcp_lite_prove(sk, pk.as_bytes(), ctx)
}

/// Verifies a KCP-Lite proof for `pk` and `ctx`.
///
/// Returns `true` only when the commitment matches `pk`, the Ed25519 signature
/// verifies, the anchor binds the proof to `ctx`, and the proof is not all-zero.
///
/// # Untrusted Input
///
/// This function accepts data from untrusted sources. All structural checks are
/// performed before any arithmetic. Malformed input is rejected with `false`
/// rather than panicking.
///
/// # Security
///
/// The public key and context must be the expected values for the active
/// handshake. Passing attacker-chosen context can make a valid proof authorize
/// the wrong transcript.
pub fn kcp_lite_verify(pk: &[u8; 32], ctx: &[u8], proof: &KcpLiteProof) -> bool {
    if !ct_eq(&proof.commitment, pk) {
        return false;
    }

    let verifying_key = match VerifyingKey::from_bytes(pk) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&proof.response);
    if verifying_key
        .verify(&proof_message(pk, ctx), &signature)
        .is_err()
    {
        return false;
    }

    let mut bind_input = Vec::with_capacity(KCP_LITE_ANCHOR_LABEL.len() + 32 + 64 + ctx.len());
    bind_input.extend_from_slice(KCP_LITE_ANCHOR_LABEL);
    bind_input.extend_from_slice(pk);
    bind_input.extend_from_slice(&proof.response);
    bind_input.extend_from_slice(ctx);
    let expected_anchor = sha3_256(&bind_input);
    if !ct_eq(&proof.anchor, &expected_anchor) {
        return false;
    }

    let zero = [0u8; 32];
    proof.commitment != zero && proof.response != [0u8; 64] && proof.anchor != zero
}

/// Placeholder for reserved strict KCP proof generation.
///
/// # Errors
///
/// Always returns [`EirnError::StrictModeUnavailable`] because strict
/// lattice-native KCP is not implemented in this crate version.
///
/// # Security
///
/// Callers must treat strict mode as unavailable rather than falling back
/// silently to KCP-Lite.
pub fn kcp_strict_prove() -> Result<()> {
    Err(EirnError::StrictModeUnavailable)
}

fn proof_message(pk: &[u8; 32], ctx: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(KCP_LITE_SIGN_LABEL.len() + pk.len() + ctx.len());
    message.extend_from_slice(KCP_LITE_SIGN_LABEL);
    message.extend_from_slice(pk);
    message.extend_from_slice(ctx);
    message
}
