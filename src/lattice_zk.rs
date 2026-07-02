//! Lattice-native proof relation helpers for KCP-Strict.
//!
//! The relation is a compact SIS-style linear relation over `Z_q`: a prover
//! knows a short witness `s` such that `t = A * s mod q`, where `A` is expanded
//! from the public key material and `t` is stored in the public key. KCP-Strict
//! proves this relation non-interactively with Fiat-Shamir transcript binding.

use crate::util::{sha3_256, shake256};

pub const Q: i32 = 3329;
pub const WITNESS_DIM: usize = 64;
pub const STATEMENT_DIM: usize = 32;
pub const STATEMENT_BYTES: usize = STATEMENT_DIM * 2;
pub const COMMITMENT_BYTES: usize = STATEMENT_BYTES;
pub const RESPONSE_BYTES: usize = WITNESS_DIM * 2;
pub const STRICT_PROOF_BYTES: usize = COMMITMENT_BYTES + RESPONSE_BYTES + 32;
pub const MASK_BOUND: i16 = 12_000;
pub const RESPONSE_BOUND: i16 = 16_095;

const WITNESS_LABEL: &[u8] = b"eirn-kcp-strict-witness-v1";
const MATRIX_LABEL: &[u8] = b"eirn-kcp-strict-matrix-v1";
const MASK_LABEL: &[u8] = b"eirn-kcp-strict-mask-v1";
const CHALLENGE_LABEL: &[u8] = b"eirn-kcp-strict-challenge-v1";

pub fn derive_witness(kem_seed: &[u8; 64], sig_seed: &[u8; 32]) -> [i16; WITNESS_DIM] {
    let mut input = Vec::with_capacity(WITNESS_LABEL.len() + kem_seed.len() + sig_seed.len());
    input.extend_from_slice(WITNESS_LABEL);
    input.extend_from_slice(kem_seed);
    input.extend_from_slice(sig_seed);
    let bytes = shake256(&input, WITNESS_DIM);

    let mut witness = [0i16; WITNESS_DIM];
    for (dst, byte) in witness.iter_mut().zip(bytes.iter()) {
        *dst = match byte % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        };
    }
    witness
}

pub fn derive_mask(secret: &[u8; 32], pk: &[u8], ctx: &[u8]) -> [i16; WITNESS_DIM] {
    let mut input = Vec::with_capacity(MASK_LABEL.len() + secret.len() + pk.len() + ctx.len());
    input.extend_from_slice(MASK_LABEL);
    input.extend_from_slice(secret);
    input.extend_from_slice(pk);
    input.extend_from_slice(ctx);
    let bytes = shake256(&input, WITNESS_DIM * 2);

    let mut mask = [0i16; WITNESS_DIM];
    for (dst, chunk) in mask.iter_mut().zip(bytes.chunks_exact(2)) {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]) as i32;
        let span = i32::from(MASK_BOUND) * 2 + 1;
        *dst = (value % span - i32::from(MASK_BOUND)) as i16;
    }
    mask
}

pub fn statement_from_witness(
    public_seed: &[u8],
    witness: &[i16; WITNESS_DIM],
) -> [u16; STATEMENT_DIM] {
    matrix_mul(public_seed, witness)
}

pub fn matrix_mul(public_seed: &[u8], vector: &[i16; WITNESS_DIM]) -> [u16; STATEMENT_DIM] {
    let matrix = expand_matrix(public_seed);
    let mut out = [0u16; STATEMENT_DIM];
    for row in 0..STATEMENT_DIM {
        let mut acc = 0i64;
        for col in 0..WITNESS_DIM {
            acc += i64::from(matrix[row * WITNESS_DIM + col]) * i64::from(vector[col]);
        }
        out[row] = mod_q(acc);
    }
    out
}

pub fn challenge(
    pk: &[u8],
    ctx: &[u8],
    statement: &[u16; STATEMENT_DIM],
    commitment: &[u16; STATEMENT_DIM],
) -> u16 {
    let mut input = Vec::with_capacity(
        CHALLENGE_LABEL.len() + pk.len() + ctx.len() + STATEMENT_BYTES + COMMITMENT_BYTES,
    );
    input.extend_from_slice(CHALLENGE_LABEL);
    input.extend_from_slice(pk);
    input.extend_from_slice(ctx);
    input.extend_from_slice(&encode_statement(statement));
    input.extend_from_slice(&encode_statement(commitment));
    let digest = sha3_256(&input);
    (u16::from_le_bytes([digest[0], digest[1]]) % 4095) + 1
}

pub fn encode_statement(values: &[u16; STATEMENT_DIM]) -> [u8; STATEMENT_BYTES] {
    let mut out = [0u8; STATEMENT_BYTES];
    for (chunk, value) in out.chunks_exact_mut(2).zip(values.iter()) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    out
}

pub fn decode_statement(bytes: &[u8]) -> Option<[u16; STATEMENT_DIM]> {
    if bytes.len() != STATEMENT_BYTES {
        return None;
    }
    let mut out = [0u16; STATEMENT_DIM];
    for (dst, chunk) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        if i32::from(value) >= Q {
            return None;
        }
        *dst = value;
    }
    Some(out)
}

pub fn encode_response(values: &[i16; WITNESS_DIM]) -> [u8; RESPONSE_BYTES] {
    let mut out = [0u8; RESPONSE_BYTES];
    for (chunk, value) in out.chunks_exact_mut(2).zip(values.iter()) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    out
}

pub fn decode_response(bytes: &[u8]) -> Option<[i16; WITNESS_DIM]> {
    if bytes.len() != RESPONSE_BYTES {
        return None;
    }
    let mut out = [0i16; WITNESS_DIM];
    for (dst, chunk) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let value = i16::from_le_bytes([chunk[0], chunk[1]]);
        if value.unsigned_abs() > RESPONSE_BOUND as u16 {
            return None;
        }
        *dst = value;
    }
    Some(out)
}

pub fn add_scaled_statement(
    commitment: &[u16; STATEMENT_DIM],
    statement: &[u16; STATEMENT_DIM],
    challenge: u16,
) -> [u16; STATEMENT_DIM] {
    let mut out = [0u16; STATEMENT_DIM];
    for ((dst, u), t) in out.iter_mut().zip(commitment.iter()).zip(statement.iter()) {
        *dst = mod_q(i64::from(*u) + i64::from(challenge) * i64::from(*t));
    }
    out
}

pub fn public_seed_from_key(pk: &[u8], kem_pk_bytes: usize, sig_pk_bytes: usize) -> &[u8] {
    &pk[..kem_pk_bytes + sig_pk_bytes]
}

pub fn statement_bytes_from_key(pk: &[u8], kem_pk_bytes: usize, sig_pk_bytes: usize) -> &[u8] {
    &pk[kem_pk_bytes + sig_pk_bytes..kem_pk_bytes + sig_pk_bytes + STATEMENT_BYTES]
}

fn expand_matrix(public_seed: &[u8]) -> Vec<u16> {
    let mut input = Vec::with_capacity(MATRIX_LABEL.len() + public_seed.len());
    input.extend_from_slice(MATRIX_LABEL);
    input.extend_from_slice(public_seed);
    let bytes = shake256(&input, STATEMENT_DIM * WITNESS_DIM * 2);
    bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]) % Q as u16)
        .collect()
}

fn mod_q(value: i64) -> u16 {
    let q = i64::from(Q);
    let mut reduced = value % q;
    if reduced < 0 {
        reduced += q;
    }
    reduced as u16
}
