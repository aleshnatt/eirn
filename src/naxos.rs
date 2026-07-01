use crate::{
    kem::{decaps, encaps_deterministic, Ciphertext, PublicKey, SecretKey},
    util::sha3_256,
};

const NAXOS_LABEL: &[u8] = b"eirn-naxos-v1";

pub fn naxos_derive_coins(
    sender_sk: &SecretKey,
    sender_ephemeral_sk: &SecretKey,
    recipient_pk: &PublicKey,
    context: &[u8],
) -> [u8; 32] {
    let h_esk = sha3_256(sender_ephemeral_sk.seed());
    let mut input = Vec::with_capacity(32 + 32 + 32 + context.len() + NAXOS_LABEL.len());
    input.extend_from_slice(sender_sk.seed());
    input.extend_from_slice(&h_esk);
    input.extend_from_slice(recipient_pk.as_bytes());
    input.extend_from_slice(context);
    input.extend_from_slice(NAXOS_LABEL);
    sha3_256(&input)
}

pub fn naxos_encaps(
    recipient_pk: &PublicKey,
    sender_sk: &SecretKey,
    sender_ephemeral_sk: &SecretKey,
    context: &[u8],
) -> (Ciphertext, [u8; 32]) {
    let coins = naxos_derive_coins(sender_sk, sender_ephemeral_sk, recipient_pk, context);
    let (ct, ss_raw) = encaps_deterministic(recipient_pk, &coins);
    let mut input = Vec::with_capacity(8 + 32 + 32 + 32 + context.len());
    input.extend_from_slice(b"naxos-ss");
    input.extend_from_slice(&ss_raw);
    input.extend_from_slice(sender_sk.public_key_bytes());
    input.extend_from_slice(recipient_pk.as_bytes());
    input.extend_from_slice(context);
    (ct, sha3_256(&input))
}

pub fn naxos_decaps(
    recipient_sk: &SecretKey,
    ct: &Ciphertext,
    sender_pk: &PublicKey,
    context: &[u8],
) -> [u8; 32] {
    let ss_raw = decaps(recipient_sk, ct);
    let mut input = Vec::with_capacity(8 + 32 + 32 + 32 + context.len());
    input.extend_from_slice(b"naxos-ss");
    input.extend_from_slice(&ss_raw);
    input.extend_from_slice(sender_pk.as_bytes());
    input.extend_from_slice(recipient_sk.public_key_bytes());
    input.extend_from_slice(context);
    sha3_256(&input)
}
