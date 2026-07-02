//! KCP-Lite key consistency proofs.
//!
//! This module implements a signature-backed consistency proof for the current
//! Eirn-KCP handshake mode. Proofs use FIPS 204 ML-DSA signatures over the
//! session context and bind the resulting signature with an anchor hash.

use ml_dsa::{MlDsa65, MlDsa87, Signature, Verifier, VerifyingKey};

use crate::{
    error::{EirnError, Result},
    kem::{PublicKey, SecretKey},
    lattice_zk,
    params::{EirnParams, PARAMS_1024, PARAMS_768},
    util::{ct_eq, sha3_256},
};

const KCP_LITE_SIGN_LABEL: &[u8] = b"eirn-kcp-lite-ml-dsa-v1";
const KCP_LITE_ANCHOR_LABEL: &[u8] = b"eirn-kcp-lite-anchor-v1";
const KCP_STRICT_ANCHOR_LABEL: &[u8] = b"eirn-kcp-strict-anchor-v1";

/// Handshake key consistency mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KcpMode {
    /// ML-DSA-backed KCP-Lite mode.
    Lite = 0x00,
    /// Reserved for a future strict proof mode.
    Strict = 0x01,
}

/// A lightweight key consistency proof for Eirn-KCP.
///
/// The proof is an ML-DSA signature over the session context plus an anchor hash
/// binding the encoded proof. It carries proof of possession of the sender
/// signing key for the supplied context, not anonymity or witness hiding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KcpLiteProof {
    pub commitment: [u8; 32],
    pub response: Vec<u8>,
    pub anchor: [u8; 32],
}

/// Lattice-native zero-knowledge proof for KCP-Strict.
///
/// The public statement is the lattice relation `t = A*s mod q`, where `A` is
/// expanded from the public key material and `t` is embedded in the public key.
/// The witness `s` is a short vector derived from the sender secret key. The
/// proof is a Fiat-Shamir transform of the lattice identification relation and
/// is bound to the session transcript by the challenge and anchor hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KcpStrictProof {
    pub commitment: [u8; lattice_zk::COMMITMENT_BYTES],
    pub response: [u8; lattice_zk::RESPONSE_BYTES],
    pub anchor: [u8; 32],
}

impl KcpStrictProof {
    /// Fixed encoded KCP-Strict proof size in bytes.
    pub const SIZE: usize = lattice_zk::STRICT_PROOF_BYTES;

    /// Serializes the proof to its fixed-size wire encoding.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..lattice_zk::COMMITMENT_BYTES].copy_from_slice(&self.commitment);
        out[lattice_zk::COMMITMENT_BYTES
            ..lattice_zk::COMMITMENT_BYTES + lattice_zk::RESPONSE_BYTES]
            .copy_from_slice(&self.response);
        out[lattice_zk::COMMITMENT_BYTES + lattice_zk::RESPONSE_BYTES..]
            .copy_from_slice(&self.anchor);
        out
    }

    /// Parses a KCP-Strict proof from its fixed-size wire encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SIZE {
            return Err(EirnError::InvalidProofLength {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        let mut commitment = [0u8; lattice_zk::COMMITMENT_BYTES];
        let mut response = [0u8; lattice_zk::RESPONSE_BYTES];
        let mut anchor = [0u8; 32];
        commitment.copy_from_slice(&data[..lattice_zk::COMMITMENT_BYTES]);
        response.copy_from_slice(
            &data[lattice_zk::COMMITMENT_BYTES
                ..lattice_zk::COMMITMENT_BYTES + lattice_zk::RESPONSE_BYTES],
        );
        anchor.copy_from_slice(&data[lattice_zk::COMMITMENT_BYTES + lattice_zk::RESPONSE_BYTES..]);

        lattice_zk::decode_statement(&commitment).ok_or(EirnError::AuthenticationFailed)?;
        lattice_zk::decode_response(&response).ok_or(EirnError::AuthenticationFailed)?;

        Ok(Self {
            commitment,
            response,
            anchor,
        })
    }
}

impl KcpLiteProof {
    /// Fixed encoded KCP-Lite proof size in bytes for the default profile.
    pub const SIZE: usize = 3373;

    /// Serializes the proof to its fixed-size wire encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.response.len() + 32);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.response);
        out.extend_from_slice(&self.anchor);
        out
    }

    /// Parses a default-profile proof from its fixed-size wire encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::from_bytes_with_params(data, PARAMS_768)
    }

    /// Parses a proof from its fixed-size wire encoding under `params`.
    pub fn from_bytes_with_params(data: &[u8], params: EirnParams) -> Result<Self> {
        if data.len() != params.proof_bytes {
            return Err(EirnError::InvalidProofLength {
                expected: params.proof_bytes,
                actual: data.len(),
            });
        }
        let mut commitment = [0u8; 32];
        let mut anchor = [0u8; 32];
        commitment.copy_from_slice(&data[..32]);
        let response = data[32..32 + params.sig_bytes].to_vec();
        anchor.copy_from_slice(&data[32 + params.sig_bytes..]);
        parse_signature(&response, params)?;
        Ok(Self {
            commitment,
            response,
            anchor,
        })
    }
}

/// Creates a KCP-Lite proof for `pk` and `ctx`.
pub fn kcp_lite_prove(sk: &SecretKey, pk: &[u8], ctx: &[u8]) -> Result<KcpLiteProof> {
    if !ct_eq(sk.public_key_bytes(), pk) {
        return Err(EirnError::KeyMismatch);
    }

    let params = sk.params();
    let vk_bytes = verifying_key_bytes(pk, params)?;
    let commitment = sha3_256(vk_bytes);
    let message = proof_message(&commitment, pk, ctx);
    let response = sk.sign_proof_message(&message);
    let anchor = proof_anchor(&commitment, &response, ctx);

    Ok(KcpLiteProof {
        commitment,
        response,
        anchor,
    })
}

/// Creates a KCP-Lite proof using a typed public key.
pub fn kcp_lite_prove_for_key(sk: &SecretKey, pk: &PublicKey, ctx: &[u8]) -> Result<KcpLiteProof> {
    if !sk.matches_public_key(pk) {
        return Err(EirnError::KeyMismatch);
    }
    kcp_lite_prove(sk, pk.as_bytes(), ctx)
}

/// Verifies a KCP-Lite proof for `pk` and `ctx`.
pub fn kcp_lite_verify(pk: &[u8], ctx: &[u8], proof: &KcpLiteProof) -> bool {
    let params = match params_from_public_key_len(pk.len()) {
        Some(params) => params,
        None => return false,
    };
    let vk_bytes = match verifying_key_bytes(pk, params) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let expected_commitment = sha3_256(vk_bytes);
    if !ct_eq(&proof.commitment, &expected_commitment) {
        return false;
    }

    if proof.response.len() != params.sig_bytes {
        return false;
    }

    if !verify_signature(
        vk_bytes,
        &proof_message(&proof.commitment, pk, ctx),
        proof,
        params,
    ) {
        return false;
    }

    let expected_anchor = proof_anchor(&proof.commitment, &proof.response, ctx);
    if !ct_eq(&proof.anchor, &expected_anchor) {
        return false;
    }

    let zero = [0u8; 32];
    proof.commitment != zero && proof.anchor != zero && proof.response.iter().any(|b| *b != 0)
}

/// Creates a lattice-native KCP-Strict proof for `pk` and `ctx`.
pub fn kcp_strict_prove(sk: &SecretKey, pk: &PublicKey, ctx: &[u8]) -> Result<KcpStrictProof> {
    if !sk.matches_public_key(pk) {
        return Err(EirnError::KeyMismatch);
    }

    let params = pk.params();
    let statement = strict_statement(pk.as_bytes(), params)?;
    let witness = sk.strict_witness();
    let mask = lattice_zk::derive_mask(&sk.commitment_secret(), pk.as_bytes(), ctx);
    let commitment = lattice_zk::matrix_mul(sk.strict_public_seed(), &mask);
    let challenge = lattice_zk::challenge(pk.as_bytes(), ctx, &statement, &commitment);

    let mut response = [0i16; lattice_zk::WITNESS_DIM];
    for ((dst, r), s) in response.iter_mut().zip(mask.iter()).zip(witness.iter()) {
        *dst = *r + (challenge as i16) * *s;
        if dst.unsigned_abs() > lattice_zk::RESPONSE_BOUND as u16 {
            return Err(EirnError::AuthenticationFailed);
        }
    }

    let commitment = lattice_zk::encode_statement(&commitment);
    let response = lattice_zk::encode_response(&response);
    let anchor = strict_anchor(pk.as_bytes(), ctx, &statement, &commitment, &response);

    Ok(KcpStrictProof {
        commitment,
        response,
        anchor,
    })
}

/// Verifies a lattice-native KCP-Strict proof for `pk` and `ctx`.
pub fn kcp_strict_verify(pk: &PublicKey, ctx: &[u8], proof: &KcpStrictProof) -> bool {
    let params = pk.params();
    let statement = match strict_statement(pk.as_bytes(), params) {
        Ok(statement) => statement,
        Err(_) => return false,
    };
    let commitment = match lattice_zk::decode_statement(&proof.commitment) {
        Some(commitment) => commitment,
        None => return false,
    };
    let response = match lattice_zk::decode_response(&proof.response) {
        Some(response) => response,
        None => return false,
    };

    let challenge = lattice_zk::challenge(pk.as_bytes(), ctx, &statement, &commitment);
    let lhs = lattice_zk::matrix_mul(
        lattice_zk::public_seed_from_key(pk.as_bytes(), params.kem_pk_bytes, params.sig_pk_bytes),
        &response,
    );
    let rhs = lattice_zk::add_scaled_statement(&commitment, &statement, challenge);
    if lhs != rhs {
        return false;
    }

    let expected_anchor = strict_anchor(
        pk.as_bytes(),
        ctx,
        &statement,
        &proof.commitment,
        &proof.response,
    );
    ct_eq(&proof.anchor, &expected_anchor)
}

fn params_from_public_key_len(len: usize) -> Option<EirnParams> {
    match len {
        len if len == PARAMS_768.pk_bytes => Some(PARAMS_768),
        len if len == PARAMS_1024.pk_bytes => Some(PARAMS_1024),
        _ => None,
    }
}

fn verifying_key_bytes(pk: &[u8], params: EirnParams) -> Result<&[u8]> {
    if pk.len() != params.pk_bytes {
        return Err(EirnError::InvalidKeyLength {
            expected: params.pk_bytes,
            actual: pk.len(),
        });
    }
    Ok(&pk[params.kem_pk_bytes..params.kem_pk_bytes + params.sig_pk_bytes])
}

fn verify_signature(
    vk_bytes: &[u8],
    message: &[u8],
    proof: &KcpLiteProof,
    params: EirnParams,
) -> bool {
    match params {
        PARAMS_768 => {
            let verifying_key = match parse_verifying_key_65(vk_bytes, params) {
                Ok(key) => key,
                Err(_) => return false,
            };
            let signature = match parse_signature_65(&proof.response, params) {
                Ok(sig) => sig,
                Err(_) => return false,
            };
            verifying_key.verify(message, &signature).is_ok()
        }
        PARAMS_1024 => {
            let verifying_key = match parse_verifying_key_87(vk_bytes, params) {
                Ok(key) => key,
                Err(_) => return false,
            };
            let signature = match parse_signature_87(&proof.response, params) {
                Ok(sig) => sig,
                Err(_) => return false,
            };
            verifying_key.verify(message, &signature).is_ok()
        }
        _ => false,
    }
}

fn parse_verifying_key_65(data: &[u8], params: EirnParams) -> Result<VerifyingKey<MlDsa65>> {
    let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(data).map_err(|_| {
        EirnError::InvalidKeyLength {
            expected: params.sig_pk_bytes,
            actual: data.len(),
        }
    })?;
    Ok(VerifyingKey::<MlDsa65>::decode(&encoded))
}

fn parse_verifying_key_87(data: &[u8], params: EirnParams) -> Result<VerifyingKey<MlDsa87>> {
    let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(data).map_err(|_| {
        EirnError::InvalidKeyLength {
            expected: params.sig_pk_bytes,
            actual: data.len(),
        }
    })?;
    Ok(VerifyingKey::<MlDsa87>::decode(&encoded))
}

fn parse_signature(data: &[u8], params: EirnParams) -> Result<()> {
    match params {
        PARAMS_768 => parse_signature_65(data, params).map(|_| ()),
        PARAMS_1024 => parse_signature_87(data, params).map(|_| ()),
        _ => Err(EirnError::UnsupportedParameterSet { name: params.name }),
    }
}

fn parse_signature_65(data: &[u8], params: EirnParams) -> Result<Signature<MlDsa65>> {
    Signature::<MlDsa65>::try_from(data).map_err(|_| EirnError::InvalidProofLength {
        expected: params.sig_bytes,
        actual: data.len(),
    })
}

fn parse_signature_87(data: &[u8], params: EirnParams) -> Result<Signature<MlDsa87>> {
    Signature::<MlDsa87>::try_from(data).map_err(|_| EirnError::InvalidProofLength {
        expected: params.sig_bytes,
        actual: data.len(),
    })
}

fn proof_message(commitment: &[u8; 32], pk: &[u8], ctx: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(KCP_LITE_SIGN_LABEL.len() + 32 + pk.len() + ctx.len());
    message.extend_from_slice(KCP_LITE_SIGN_LABEL);
    message.extend_from_slice(commitment);
    message.extend_from_slice(pk);
    message.extend_from_slice(ctx);
    message
}

fn proof_anchor(commitment: &[u8; 32], response: &[u8], ctx: &[u8]) -> [u8; 32] {
    let mut bind_input =
        Vec::with_capacity(KCP_LITE_ANCHOR_LABEL.len() + 32 + response.len() + ctx.len());
    bind_input.extend_from_slice(KCP_LITE_ANCHOR_LABEL);
    bind_input.extend_from_slice(commitment);
    bind_input.extend_from_slice(response);
    bind_input.extend_from_slice(ctx);
    sha3_256(&bind_input)
}

fn strict_statement(pk: &[u8], params: EirnParams) -> Result<[u16; lattice_zk::STATEMENT_DIM]> {
    if pk.len() != params.pk_bytes {
        return Err(EirnError::InvalidKeyLength {
            expected: params.pk_bytes,
            actual: pk.len(),
        });
    }
    lattice_zk::decode_statement(lattice_zk::statement_bytes_from_key(
        pk,
        params.kem_pk_bytes,
        params.sig_pk_bytes,
    ))
    .ok_or(EirnError::AuthenticationFailed)
}

fn strict_anchor(
    pk: &[u8],
    ctx: &[u8],
    statement: &[u16; lattice_zk::STATEMENT_DIM],
    commitment: &[u8],
    response: &[u8],
) -> [u8; 32] {
    let statement = lattice_zk::encode_statement(statement);
    let mut input = Vec::with_capacity(
        KCP_STRICT_ANCHOR_LABEL.len()
            + pk.len()
            + ctx.len()
            + statement.len()
            + commitment.len()
            + response.len(),
    );
    input.extend_from_slice(KCP_STRICT_ANCHOR_LABEL);
    input.extend_from_slice(pk);
    input.extend_from_slice(ctx);
    input.extend_from_slice(&statement);
    input.extend_from_slice(commitment);
    input.extend_from_slice(response);
    sha3_256(&input)
}
