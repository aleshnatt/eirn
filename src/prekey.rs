use core::fmt;

use crate::{
    error::{EirnError, Result},
    kem::{keygen_with_params, PublicKey, SecretKey},
    params::{EirnParams, PARAMS_512},
    util::sha3_256,
};

const PREKEY_COMMIT_LABEL: &[u8] = b"eirn-prekey-commit-v1";

pub struct PrekeyBundle {
    pub identity_pk: PublicKey,
    pub identity_sk: SecretKey,
    pub signed_prekey_pk: PublicKey,
    pub signed_prekey_sk: SecretKey,
    pub one_time_prekeys: Vec<(PublicKey, SecretKey)>,
    pub commitment: [u8; 32],
}

impl fmt::Debug for PrekeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrekeyBundle")
            .field("identity_pk", &self.identity_pk)
            .field("identity_sk", &"<redacted>")
            .field("signed_prekey_pk", &self.signed_prekey_pk)
            .field("signed_prekey_sk", &"<redacted>")
            .field(
                "one_time_prekeys",
                &format_args!("{} entries", self.one_time_prekeys.len()),
            )
            .field("commitment", &self.commitment)
            .finish()
    }
}

impl PrekeyBundle {
    pub fn consume_opk(&mut self) -> Result<(PublicKey, SecretKey)> {
        if self.one_time_prekeys.is_empty() {
            return Err(EirnError::NoOneTimePrekeys);
        }
        Ok(self.one_time_prekeys.remove(0))
    }
}

pub fn generate_prekey_bundle(num_opk: usize) -> PrekeyBundle {
    generate_prekey_bundle_with_params(num_opk, PARAMS_512)
}

pub fn generate_prekey_bundle_with_params(num_opk: usize, params: EirnParams) -> PrekeyBundle {
    let (identity_pk, identity_sk) = keygen_with_params(params);
    let (signed_prekey_pk, signed_prekey_sk) = keygen_with_params(params);
    let one_time_prekeys = (0..num_opk).map(|_| keygen_with_params(params)).collect();

    let mut input = Vec::with_capacity(32 + 32 + PREKEY_COMMIT_LABEL.len());
    input.extend_from_slice(signed_prekey_sk.seed());
    input.extend_from_slice(signed_prekey_pk.as_bytes());
    input.extend_from_slice(PREKEY_COMMIT_LABEL);
    let commitment = sha3_256(&input);

    PrekeyBundle {
        identity_pk,
        identity_sk,
        signed_prekey_pk,
        signed_prekey_sk,
        one_time_prekeys,
        commitment,
    }
}
