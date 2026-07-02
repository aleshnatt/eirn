//! Receiver prekey bundle generation and consumption.
//!
//! This module builds the public and private state used by asynchronous senders.
//! It is designed to let senders operate from a public bundle while receivers
//! keep secret keys local and consume one-time prekeys. It does not authenticate
//! bundle distribution; applications must provide that channel.

use core::fmt;

use crate::{
    error::{EirnError, Result},
    kem::{keygen_with_params, PublicKey, SecretKey},
    params::{EirnParams, PARAMS_512},
    util::sha3_256,
};

const PREKEY_COMMIT_LABEL: &[u8] = b"eirn-prekey-commit-v1";

/// Public receiver prekey material distributed to senders.
///
/// The bundle exposes the receiver identity key, signed prekey, one-time
/// prekeys, and a commitment to the private signed-prekey state. It carries no
/// receiver secret material. Callers must authenticate the bundle before using
/// it to create a sender handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicPrekeyBundle {
    pub identity_pk: PublicKey,
    pub signed_prekey_pk: PublicKey,
    pub one_time_prekeys: Vec<PublicKey>,
    pub commitment: [u8; 32],
}

/// Receiver-owned prekey state for accepting asynchronous handshakes.
///
/// The bundle stores identity, signed-prekey, and one-time-prekey secret keys.
/// Its debug output redacts private keys, and `consume_opk` removes one-time
/// keys as they are used. Callers must keep this state private and avoid using
/// the same one-time prekey for multiple accepted messages.
pub struct PrekeyBundle {
    pub identity_pk: PublicKey,
    identity_sk: SecretKey,
    pub signed_prekey_pk: PublicKey,
    signed_prekey_sk: SecretKey,
    pub one_time_prekeys: Vec<PublicKey>,
    one_time_secret_keys: Vec<SecretKey>,
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
    /// Returns the public prekey bundle for distribution to senders.
    ///
    /// # Security
    ///
    /// The returned bundle contains no secret keys, but it is not self
    /// authenticating. Applications must sign, publish, or otherwise authenticate
    /// it before senders rely on it.
    pub fn public_bundle(&self) -> PublicPrekeyBundle {
        PublicPrekeyBundle {
            identity_pk: self.identity_pk.clone(),
            signed_prekey_pk: self.signed_prekey_pk.clone(),
            one_time_prekeys: self.one_time_prekeys.clone(),
            commitment: self.commitment,
        }
    }

    /// Removes and returns the next one-time prekey pair.
    ///
    /// # Errors
    ///
    /// Returns [`EirnError::NoOneTimePrekeys`] if the bundle has no one-time
    /// prekeys left.
    ///
    /// # Security
    ///
    /// This method enforces local one-time use by removing the returned key
    /// pair. Callers must persist the updated bundle state before accepting a
    /// handshake in systems where crashes can roll state back.
    pub fn consume_opk(&mut self) -> Result<(PublicKey, SecretKey)> {
        if self.one_time_prekeys.is_empty() {
            return Err(EirnError::NoOneTimePrekeys);
        }
        Ok((
            self.one_time_prekeys.remove(0),
            self.one_time_secret_keys.remove(0),
        ))
    }

    pub(crate) fn identity_sk(&self) -> &SecretKey {
        &self.identity_sk
    }

    pub(crate) fn signed_prekey_sk(&self) -> &SecretKey {
        &self.signed_prekey_sk
    }
}

/// Generates receiver prekey state under the default Eirn-512 profile.
///
/// # Randomness
///
/// This function uses `OsRng` through key generation. Fresh randomness is
/// required for every identity, signed-prekey, and one-time-prekey secret.
///
/// # Security
///
/// The returned bundle contains private receiver state. Publish only
/// [`PrekeyBundle::public_bundle`].
pub fn generate_prekey_bundle(num_opk: usize) -> PrekeyBundle {
    generate_prekey_bundle_with_params(num_opk, PARAMS_512)
}

/// Generates receiver prekey state under `params`.
///
/// # Randomness
///
/// This function uses `OsRng` through key generation. Fresh randomness is
/// required for every identity, signed-prekey, and one-time-prekey secret.
///
/// # Security
///
/// `num_opk` controls how many messages can consume one-time prekeys before
/// receiver state must be refreshed. The returned private bundle must be stored
/// securely.
pub fn generate_prekey_bundle_with_params(num_opk: usize, params: EirnParams) -> PrekeyBundle {
    let (identity_pk, identity_sk) = keygen_with_params(params);
    let (signed_prekey_pk, signed_prekey_sk) = keygen_with_params(params);
    let mut one_time_prekeys = Vec::with_capacity(num_opk);
    let mut one_time_secret_keys = Vec::with_capacity(num_opk);
    for _ in 0..num_opk {
        let (pk, sk) = keygen_with_params(params);
        one_time_prekeys.push(pk);
        one_time_secret_keys.push(sk);
    }

    let mut commitment_input = Vec::with_capacity(32 + 32 + PREKEY_COMMIT_LABEL.len());
    commitment_input.extend_from_slice(signed_prekey_sk.seed());
    commitment_input.extend_from_slice(signed_prekey_pk.as_bytes());
    commitment_input.extend_from_slice(PREKEY_COMMIT_LABEL);
    let commitment = sha3_256(&commitment_input);

    PrekeyBundle {
        identity_pk,
        identity_sk,
        signed_prekey_pk,
        signed_prekey_sk,
        one_time_prekeys,
        one_time_secret_keys,
        commitment,
    }
}
