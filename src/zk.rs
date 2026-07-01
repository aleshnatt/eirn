use rand_core::{CryptoRng, OsRng, RngCore};

use crate::{
    error::{EirnError, Result},
    kem::{PublicKey, SecretKey, KEY_DERIVE_PREFIX},
    util::{ct_eq, sha3_256},
};

const ZK_AUTH_LABEL: &[u8] = b"eirn-zk-auth-v1";
const ZK_BIND_LABEL: &[u8] = b"eirn-zk-binding-v1";

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KcpLiteProof {
    pub commitment: [u8; 32],
    pub response: [u8; 32],
    pub anchor: [u8; 32],
}

impl KcpLiteProof {
    pub const SIZE: usize = 96;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..32].copy_from_slice(&self.commitment);
        out[32..64].copy_from_slice(&self.response);
        out[64..].copy_from_slice(&self.anchor);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SIZE {
            return Err(EirnError::InvalidProofLength {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }
        let mut commitment = [0u8; 32];
        let mut response = [0u8; 32];
        let mut anchor = [0u8; 32];
        commitment.copy_from_slice(&data[..32]);
        response.copy_from_slice(&data[32..64]);
        anchor.copy_from_slice(&data[64..]);
        Ok(Self {
            commitment,
            response,
            anchor,
        })
    }
}

pub fn kcp_lite_prove(sk_seed: &[u8; 32], pk: &[u8; 32], ctx: &[u8]) -> Result<KcpLiteProof> {
    kcp_lite_prove_with_rng(&mut OsRng, sk_seed, pk, ctx)
}

pub fn kcp_lite_prove_for_key(sk: &SecretKey, pk: &PublicKey, ctx: &[u8]) -> Result<KcpLiteProof> {
    if !sk.matches_public_key(pk) {
        return Err(EirnError::KeyMismatch);
    }
    kcp_lite_prove(sk.seed(), pk.as_bytes(), ctx)
}

pub fn kcp_lite_prove_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    sk_seed: &[u8; 32],
    pk: &[u8; 32],
    ctx: &[u8],
) -> Result<KcpLiteProof> {
    let mut witness = [0u8; 32];
    rng.fill_bytes(&mut witness);
    kcp_lite_prove_with_witness(sk_seed, pk, ctx, &witness)
}

pub fn kcp_lite_prove_with_witness(
    sk_seed: &[u8; 32],
    pk: &[u8; 32],
    ctx: &[u8],
    witness: &[u8; 32],
) -> Result<KcpLiteProof> {
    let mut pk_input = Vec::with_capacity(KEY_DERIVE_PREFIX.len() + sk_seed.len());
    pk_input.extend_from_slice(KEY_DERIVE_PREFIX);
    pk_input.extend_from_slice(sk_seed);
    let commitment = sha3_256(&pk_input);
    if !ct_eq(&commitment, pk) {
        return Err(EirnError::KeyMismatch);
    }

    let mut auth_input = Vec::with_capacity(ZK_AUTH_LABEL.len() + 32 + 32 + ctx.len());
    auth_input.extend_from_slice(ZK_AUTH_LABEL);
    auth_input.extend_from_slice(sk_seed);
    auth_input.extend_from_slice(witness);
    auth_input.extend_from_slice(ctx);
    let response = sha3_256(&auth_input);

    let mut bind_input = Vec::with_capacity(ZK_BIND_LABEL.len() + 32 + 32 + ctx.len());
    bind_input.extend_from_slice(ZK_BIND_LABEL);
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

pub fn kcp_lite_verify(pk: &[u8; 32], ctx: &[u8], proof: &KcpLiteProof) -> bool {
    if !ct_eq(&proof.commitment, pk) {
        return false;
    }

    let mut bind_input = Vec::with_capacity(ZK_BIND_LABEL.len() + 32 + 32 + ctx.len());
    bind_input.extend_from_slice(ZK_BIND_LABEL);
    bind_input.extend_from_slice(pk);
    bind_input.extend_from_slice(&proof.response);
    bind_input.extend_from_slice(ctx);
    let expected_anchor = sha3_256(&bind_input);
    if !ct_eq(&proof.anchor, &expected_anchor) {
        return false;
    }

    let zero = [0u8; 32];
    proof.commitment != zero
        && proof.response != zero
        && proof.anchor != zero
        && proof.commitment != proof.response
}

pub fn kcp_strict_prove() -> Result<()> {
    Err(EirnError::StrictModeUnavailable)
}
