//! NAXOS-style sender-bound encapsulation helpers.
//!
//! This module derives deterministic encapsulation coins from sender identity
//! and ephemeral secrets before wrapping the KEM shared secret into the
//! handshake transcript. It is intended to resist sender key-compromise
//! impersonation within the modeled Eirn-KCP flow. It does not make the
//! underlying hash-based KEM a standardized NAXOS construction.

use crate::{
    kem::{decaps, encaps_deterministic, Ciphertext, PublicKey, SecretKey},
    util::sha3_256,
};

const NAXOS_LABEL: &[u8] = b"eirn-naxos-v1";

/// Derives deterministic encapsulation coins for the sender-bound KEM leg.
///
/// # Security
///
/// Both sender secret inputs must be fresh for their intended roles: the
/// identity key binds the sender, and the ephemeral key separates sessions. The
/// `context` must include the authenticated peer and ephemeral public keys.
pub fn naxos_derive_coins(
    sender_sk: &SecretKey,
    sender_ephemeral_sk: &SecretKey,
    recipient_pk: &PublicKey,
    context: &[u8],
) -> [u8; 32] {
    let hashed_ephemeral_secret = sha3_256(sender_ephemeral_sk.seed());
    let mut coin_input = Vec::with_capacity(32 + 32 + 32 + context.len() + NAXOS_LABEL.len());
    coin_input.extend_from_slice(sender_sk.seed());
    coin_input.extend_from_slice(&hashed_ephemeral_secret);
    coin_input.extend_from_slice(recipient_pk.as_bytes());
    coin_input.extend_from_slice(context);
    coin_input.extend_from_slice(NAXOS_LABEL);
    sha3_256(&coin_input)
}

/// Encapsulates to `recipient_pk` with coins derived from sender secrets.
///
/// # Security
///
/// The returned shared secret is additionally bound to sender public bytes,
/// recipient public bytes, and `context`. Callers must ensure `context` is the
/// same on the sender and receiver paths.
pub fn naxos_encaps(
    recipient_pk: &PublicKey,
    sender_sk: &SecretKey,
    sender_ephemeral_sk: &SecretKey,
    context: &[u8],
) -> (Ciphertext, [u8; 32]) {
    let coins = naxos_derive_coins(sender_sk, sender_ephemeral_sk, recipient_pk, context);
    let (ct, ss_raw) = encaps_deterministic(recipient_pk, &coins);
    let mut ss_input = Vec::with_capacity(8 + 32 + 32 + 32 + context.len());
    ss_input.extend_from_slice(b"naxos-ss");
    ss_input.extend_from_slice(&ss_raw);
    ss_input.extend_from_slice(sender_sk.public_key_bytes());
    ss_input.extend_from_slice(recipient_pk.as_bytes());
    ss_input.extend_from_slice(context);
    (ct, sha3_256(&ss_input))
}

/// Decapsulates the sender-bound ciphertext and rebinds it to the transcript.
///
/// # Security
///
/// The caller must pass the authenticated sender public key and the same context
/// used by the sender. Mismatched inputs derive a different secret rather than
/// producing an explicit error.
pub fn naxos_decaps(
    recipient_sk: &SecretKey,
    ct: &Ciphertext,
    sender_pk: &PublicKey,
    context: &[u8],
) -> [u8; 32] {
    let ss_raw = decaps(recipient_sk, ct);
    let mut ss_input = Vec::with_capacity(8 + 32 + 32 + 32 + context.len());
    ss_input.extend_from_slice(b"naxos-ss");
    ss_input.extend_from_slice(&ss_raw);
    ss_input.extend_from_slice(sender_pk.as_bytes());
    ss_input.extend_from_slice(recipient_sk.public_key_bytes());
    ss_input.extend_from_slice(context);
    sha3_256(&ss_input)
}
