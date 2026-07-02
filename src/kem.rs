//! ML-KEM key encapsulation building blocks for Eirn-KCP.
//!
//! This module wraps the FIPS 203 ML-KEM implementations used by the handshake.
//! Public keys carry the ML-KEM encapsulation key, the ML-DSA verifying key used
//! by KCP-Lite, and the lattice statement used by KCP-Strict, so a single
//! authenticated Eirn public key binds key establishment and proof verification.

use core::fmt;

use ml_dsa::{
    Keypair as _, MlDsa65, MlDsa87, SignatureEncoding as _, Signer, SigningKey as MlDsaSigningKey,
};
use ml_kem::{
    kem::{Decapsulate, KeyExport},
    DecapsulationKey1024, DecapsulationKey768, EncapsulationKey1024, EncapsulationKey768,
    MlKem1024, MlKem768, Seed as MlKemSeed,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroize;

use crate::{
    error::{EirnError, Result},
    lattice_zk,
    params::{EirnParams, PARAMS_1024, PARAMS_768},
    util::{ct_eq, sha3_256},
};

type MlKemCiphertext768 = ml_kem::Ciphertext<MlKem768>;
type MlKemCiphertext1024 = ml_kem::Ciphertext<MlKem1024>;
type MlDsaSeed = ml_dsa::Seed;

/// Public Eirn-KCP key material for a post-quantum profile.
///
/// The encoded key is
/// `ML-KEM public key || ML-DSA verifying key || lattice statement`.
/// Applications must authenticate these bytes before accepting them as a peer
/// identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    data: Vec<u8>,
    params: EirnParams,
}

impl PublicKey {
    /// Fixed encoded public-key size in bytes for the default profile.
    pub const SIZE: usize = 3200;

    /// Returns the canonical public-key encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Parses a public key from its fixed-size byte encoding.
    pub fn from_bytes(data: &[u8], params: EirnParams) -> Result<Self> {
        ensure_supported_params(params)?;
        if data.len() != params.pk_bytes {
            return Err(EirnError::InvalidKeyLength {
                expected: params.pk_bytes,
                actual: data.len(),
            });
        }

        parse_encapsulation_key(data, params)?;
        parse_verifying_key(
            &data[params.kem_pk_bytes..params.kem_pk_bytes + params.sig_pk_bytes],
            params,
        )?;
        parse_lattice_statement(data, params)?;

        Ok(Self {
            data: data.to_vec(),
            params,
        })
    }

    /// Returns the protocol profile attached to this key.
    pub fn params(&self) -> EirnParams {
        self.params
    }
}

/// Secret Eirn-KCP key material for a post-quantum profile.
///
/// The key owns an ML-KEM decapsulation seed and an ML-DSA signing seed. Its
/// debug representation redacts both seeds.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    kem_seed: [u8; 64],
    sig_seed: [u8; 32],
    pk_data: Vec<u8>,
    #[zeroize(skip)]
    params: EirnParams,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("kem_seed", &"<redacted>")
            .field("sig_seed", &"<redacted>")
            .field("pk_data", &self.pk_data)
            .field("params", &self.params)
            .finish()
    }
}

impl SecretKey {
    pub(crate) fn commitment_secret(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(self.kem_seed.len() + self.sig_seed.len());
        input.extend_from_slice(&self.kem_seed);
        input.extend_from_slice(&self.sig_seed);
        sha3_256(&input)
    }

    pub(crate) fn sign_proof_message(&self, message: &[u8]) -> Vec<u8> {
        match self.params {
            PARAMS_768 => MlDsaSigningKey::<MlDsa65>::from_seed(&MlDsaSeed::from(self.sig_seed))
                .sign(message)
                .to_bytes()
                .to_vec(),
            PARAMS_1024 => MlDsaSigningKey::<MlDsa87>::from_seed(&MlDsaSeed::from(self.sig_seed))
                .sign(message)
                .to_bytes()
                .to_vec(),
            _ => unreachable!("SecretKey construction rejects unsupported params"),
        }
    }

    pub(crate) fn strict_witness(&self) -> [i16; lattice_zk::WITNESS_DIM] {
        lattice_zk::derive_witness(&self.kem_seed, &self.sig_seed)
    }

    pub(crate) fn strict_public_seed(&self) -> &[u8] {
        lattice_zk::public_seed_from_key(
            &self.pk_data,
            self.params.kem_pk_bytes,
            self.params.sig_pk_bytes,
        )
    }

    /// Returns the public key bytes derived from this secret key.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.pk_data
    }

    /// Returns the protocol profile attached to this key.
    pub fn params(&self) -> EirnParams {
        self.params
    }

    /// Checks whether this secret key owns the supplied public key.
    pub fn matches_public_key(&self, pk: &PublicKey) -> bool {
        self.params == pk.params && ct_eq(&self.pk_data, pk.as_bytes())
    }
}

/// Fixed-size ML-KEM encapsulation ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    data: Vec<u8>,
    params: EirnParams,
}

impl Ciphertext {
    /// Fixed encoded ciphertext size in bytes for the default profile.
    pub const SIZE: usize = 1088;

    /// Returns the canonical ciphertext encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Parses a ciphertext from its fixed-size byte encoding.
    pub fn from_bytes(data: &[u8], params: EirnParams) -> Result<Self> {
        ensure_supported_params(params)?;
        if data.len() != params.ct_bytes {
            return Err(EirnError::InvalidCiphertextLength {
                expected: params.ct_bytes,
                actual: data.len(),
            });
        }
        parse_ciphertext(data, params)?;
        Ok(Self {
            data: data.to_vec(),
            params,
        })
    }

    /// Returns the protocol profile attached to this ciphertext.
    pub fn params(&self) -> EirnParams {
        self.params
    }
}

/// Generates a key pair under the default ML-KEM-768 / ML-DSA-65 profile.
pub fn keygen() -> (PublicKey, SecretKey) {
    keygen_with_rng(&mut OsRng, PARAMS_768)
}

/// Generates a key pair under `params` using the operating-system RNG.
pub fn keygen_with_params(params: EirnParams) -> (PublicKey, SecretKey) {
    keygen_with_rng(&mut OsRng, params)
}

/// Generates a key pair under `params` using caller-supplied randomness.
pub fn keygen_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: EirnParams,
) -> (PublicKey, SecretKey) {
    let mut seed = [0u8; 96];
    rng.fill_bytes(&mut seed);
    keygen_from_seed(seed, params)
}

/// Derives a key pair deterministically from a 96-byte seed.
///
/// The first 64 bytes seed ML-KEM. The final 32 bytes seed ML-DSA.
pub fn keygen_from_seed(seed: [u8; 96], params: EirnParams) -> (PublicKey, SecretKey) {
    if !is_supported_params(params) {
        panic!("unsupported Eirn-KCP parameter set: {}", params.name);
    }

    let mut kem_seed = [0u8; 64];
    let mut sig_seed = [0u8; 32];
    kem_seed.copy_from_slice(&seed[..64]);
    sig_seed.copy_from_slice(&seed[64..]);

    let (ek_bytes, vk_bytes) = match params {
        PARAMS_768 => {
            let dk = DecapsulationKey768::from_seed(MlKemSeed::from(kem_seed));
            let sig_key = MlDsaSigningKey::<MlDsa65>::from_seed(&MlDsaSeed::from(sig_seed));
            (
                dk.encapsulation_key().to_bytes().to_vec(),
                sig_key.verifying_key().to_bytes().to_vec(),
            )
        }
        PARAMS_1024 => {
            let dk = DecapsulationKey1024::from_seed(MlKemSeed::from(kem_seed));
            let sig_key = MlDsaSigningKey::<MlDsa87>::from_seed(&MlDsaSeed::from(sig_seed));
            (
                dk.encapsulation_key().to_bytes().to_vec(),
                sig_key.verifying_key().to_bytes().to_vec(),
            )
        }
        _ => unreachable!("unsupported params rejected above"),
    };

    let mut pk_data = Vec::with_capacity(params.pk_bytes);
    pk_data.extend_from_slice(&ek_bytes);
    pk_data.extend_from_slice(&vk_bytes);
    let witness = lattice_zk::derive_witness(&kem_seed, &sig_seed);
    let statement = lattice_zk::statement_from_witness(&pk_data, &witness);
    pk_data.extend_from_slice(&lattice_zk::encode_statement(&statement));

    (
        PublicKey {
            data: pk_data.clone(),
            params,
        },
        SecretKey {
            kem_seed,
            sig_seed,
            pk_data,
            params,
        },
    )
}

/// Encapsulates to `pk` using `OsRng`.
pub fn encaps(pk: &PublicKey) -> (Ciphertext, [u8; 32]) {
    encaps_with_rng(&mut OsRng, pk)
}

/// Encapsulates to `pk` using caller-supplied randomness.
pub fn encaps_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
) -> (Ciphertext, [u8; 32]) {
    let mut coins = [0u8; 32];
    rng.fill_bytes(&mut coins);
    encaps_deterministic(pk, &coins)
}

/// Encapsulates to `pk` with explicit 32-byte ML-KEM randomness.
///
/// # Security
///
/// This is exposed for deterministic test vectors and protocol-internal
/// derivations. Normal callers should use [`encaps`].
pub fn encaps_deterministic(pk: &PublicKey, coins: &[u8; 32]) -> (Ciphertext, [u8; 32]) {
    let (ct_data, shared) = match pk.params {
        PARAMS_768 => {
            let ek = parse_encapsulation_key_768(pk.as_bytes(), pk.params)
                .expect("PublicKey values are validated at construction");
            let (ct, ss) = ek.encapsulate_deterministic(&ml_kem::B32::from(*coins));
            let ct_bytes: &[u8] = ct.as_ref();
            let mut shared = [0u8; 32];
            shared.copy_from_slice(&ss);
            (ct_bytes.to_vec(), shared)
        }
        PARAMS_1024 => {
            let ek = parse_encapsulation_key_1024(pk.as_bytes(), pk.params)
                .expect("PublicKey values are validated at construction");
            let (ct, ss) = ek.encapsulate_deterministic(&ml_kem::B32::from(*coins));
            let ct_bytes: &[u8] = ct.as_ref();
            let mut shared = [0u8; 32];
            shared.copy_from_slice(&ss);
            (ct_bytes.to_vec(), shared)
        }
        _ => unreachable!("PublicKey construction rejects unsupported params"),
    };

    (
        Ciphertext {
            data: ct_data,
            params: pk.params,
        },
        shared,
    )
}

/// Decapsulates an ML-KEM ciphertext.
pub fn decaps(sk: &SecretKey, ct: &Ciphertext) -> [u8; 32] {
    let mut shared = [0u8; 32];
    match sk.params {
        PARAMS_768 => {
            let dk = DecapsulationKey768::from_seed(MlKemSeed::from(sk.kem_seed));
            let kem_ct = parse_ciphertext_768(ct.as_bytes(), ct.params)
                .expect("Ciphertext values are validated at construction");
            shared.copy_from_slice(&dk.decapsulate(&kem_ct));
        }
        PARAMS_1024 => {
            let dk = DecapsulationKey1024::from_seed(MlKemSeed::from(sk.kem_seed));
            let kem_ct = parse_ciphertext_1024(ct.as_bytes(), ct.params)
                .expect("Ciphertext values are validated at construction");
            shared.copy_from_slice(&dk.decapsulate(&kem_ct));
        }
        _ => unreachable!("SecretKey construction rejects unsupported params"),
    }
    shared
}

fn ensure_supported_params(params: EirnParams) -> Result<()> {
    if !is_supported_params(params) {
        return Err(EirnError::UnsupportedParameterSet { name: params.name });
    }
    Ok(())
}

fn is_supported_params(params: EirnParams) -> bool {
    matches!(params, PARAMS_768 | PARAMS_1024)
}

fn parse_encapsulation_key(data: &[u8], params: EirnParams) -> Result<()> {
    match params {
        PARAMS_768 => parse_encapsulation_key_768(data, params).map(|_| ()),
        PARAMS_1024 => parse_encapsulation_key_1024(data, params).map(|_| ()),
        _ => Err(EirnError::UnsupportedParameterSet { name: params.name }),
    }
}

fn parse_encapsulation_key_768(data: &[u8], params: EirnParams) -> Result<EncapsulationKey768> {
    let kem_bytes = data
        .get(..params.kem_pk_bytes)
        .ok_or(EirnError::InvalidKeyLength {
            expected: params.pk_bytes,
            actual: data.len(),
        })?;
    let encoded = ml_kem::kem::Key::<EncapsulationKey768>::try_from(kem_bytes).map_err(|_| {
        EirnError::InvalidKeyLength {
            expected: params.kem_pk_bytes,
            actual: kem_bytes.len(),
        }
    })?;
    EncapsulationKey768::new(&encoded).map_err(|_| EirnError::AuthenticationFailed)
}

fn parse_encapsulation_key_1024(data: &[u8], params: EirnParams) -> Result<EncapsulationKey1024> {
    let kem_bytes = data
        .get(..params.kem_pk_bytes)
        .ok_or(EirnError::InvalidKeyLength {
            expected: params.pk_bytes,
            actual: data.len(),
        })?;
    let encoded = ml_kem::kem::Key::<EncapsulationKey1024>::try_from(kem_bytes).map_err(|_| {
        EirnError::InvalidKeyLength {
            expected: params.kem_pk_bytes,
            actual: kem_bytes.len(),
        }
    })?;
    EncapsulationKey1024::new(&encoded).map_err(|_| EirnError::AuthenticationFailed)
}

fn parse_ciphertext(data: &[u8], params: EirnParams) -> Result<()> {
    match params {
        PARAMS_768 => parse_ciphertext_768(data, params).map(|_| ()),
        PARAMS_1024 => parse_ciphertext_1024(data, params).map(|_| ()),
        _ => Err(EirnError::UnsupportedParameterSet { name: params.name }),
    }
}

fn parse_ciphertext_768(data: &[u8], params: EirnParams) -> Result<MlKemCiphertext768> {
    let encoded =
        MlKemCiphertext768::try_from(data).map_err(|_| EirnError::InvalidCiphertextLength {
            expected: params.ct_bytes,
            actual: data.len(),
        })?;
    Ok(encoded)
}

fn parse_ciphertext_1024(data: &[u8], params: EirnParams) -> Result<MlKemCiphertext1024> {
    let encoded =
        MlKemCiphertext1024::try_from(data).map_err(|_| EirnError::InvalidCiphertextLength {
            expected: params.ct_bytes,
            actual: data.len(),
        })?;
    Ok(encoded)
}

fn parse_verifying_key(data: &[u8], params: EirnParams) -> Result<()> {
    match params {
        PARAMS_768 => {
            let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(data).map_err(|_| {
                EirnError::InvalidKeyLength {
                    expected: params.sig_pk_bytes,
                    actual: data.len(),
                }
            })?;
            let _ = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded);
        }
        PARAMS_1024 => {
            let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(data).map_err(|_| {
                EirnError::InvalidKeyLength {
                    expected: params.sig_pk_bytes,
                    actual: data.len(),
                }
            })?;
            let _ = ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded);
        }
        _ => return Err(EirnError::UnsupportedParameterSet { name: params.name }),
    }
    Ok(())
}

fn parse_lattice_statement(data: &[u8], params: EirnParams) -> Result<()> {
    let expected = params.kem_pk_bytes + params.sig_pk_bytes + params.zk_statement_bytes;
    if data.len() != expected {
        return Err(EirnError::InvalidKeyLength {
            expected,
            actual: data.len(),
        });
    }
    lattice_zk::decode_statement(lattice_zk::statement_bytes_from_key(
        data,
        params.kem_pk_bytes,
        params.sig_pk_bytes,
    ))
    .ok_or(EirnError::AuthenticationFailed)?;
    Ok(())
}
