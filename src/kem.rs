use core::fmt;

use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroize;

use crate::{
    error::{EirnError, Result},
    params::{EirnParams, PARAMS_512},
    util::{ct_eq, sha3_256, shake256},
};

pub const KEY_DERIVE_PREFIX: &[u8] = b"eirn-keygen-pk";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    data: [u8; 32],
    params: EirnParams,
}

impl PublicKey {
    pub const SIZE: usize = 32;

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }

    pub fn from_bytes(data: &[u8], params: EirnParams) -> Result<Self> {
        let bytes: [u8; Self::SIZE] = data.try_into().map_err(|_| EirnError::InvalidKeyLength {
            expected: Self::SIZE,
            actual: data.len(),
        })?;
        Ok(Self {
            data: bytes,
            params,
        })
    }

    pub fn params(&self) -> EirnParams {
        self.params
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    seed: [u8; 32],
    pk_data: [u8; 32],
    #[zeroize(skip)]
    params: EirnParams,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("seed", &"<redacted>")
            .field("pk_data", &self.pk_data)
            .field("params", &self.params)
            .finish()
    }
}

impl SecretKey {
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.pk_data
    }

    pub fn params(&self) -> EirnParams {
        self.params
    }

    pub fn matches_public_key(&self, pk: &PublicKey) -> bool {
        self.params == pk.params && ct_eq(&self.pk_data, pk.as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    data: [u8; 64],
    params: EirnParams,
}

impl Ciphertext {
    pub const SIZE: usize = 64;

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.data
    }

    pub fn from_bytes(data: &[u8], params: EirnParams) -> Result<Self> {
        let bytes: [u8; Self::SIZE] =
            data.try_into()
                .map_err(|_| EirnError::InvalidCiphertextLength {
                    expected: Self::SIZE,
                    actual: data.len(),
                })?;
        Ok(Self {
            data: bytes,
            params,
        })
    }

    pub fn params(&self) -> EirnParams {
        self.params
    }
}

pub fn keygen() -> (PublicKey, SecretKey) {
    keygen_with_rng(&mut OsRng, PARAMS_512)
}

pub fn keygen_with_params(params: EirnParams) -> (PublicKey, SecretKey) {
    keygen_with_rng(&mut OsRng, params)
}

pub fn keygen_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: EirnParams,
) -> (PublicKey, SecretKey) {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    keygen_from_seed(seed, params)
}

pub fn keygen_from_seed(seed: [u8; 32], params: EirnParams) -> (PublicKey, SecretKey) {
    let mut pk_input = Vec::with_capacity(KEY_DERIVE_PREFIX.len() + seed.len());
    pk_input.extend_from_slice(KEY_DERIVE_PREFIX);
    pk_input.extend_from_slice(&seed);
    let pk_data = sha3_256(&pk_input);
    (
        PublicKey {
            data: pk_data,
            params,
        },
        SecretKey {
            seed,
            pk_data,
            params,
        },
    )
}

pub fn encaps(pk: &PublicKey) -> (Ciphertext, [u8; 32]) {
    encaps_with_rng(&mut OsRng, pk)
}

pub fn encaps_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
) -> (Ciphertext, [u8; 32]) {
    let mut coins = [0u8; 32];
    rng.fill_bytes(&mut coins);
    encaps_deterministic(pk, &coins)
}

pub fn encaps_deterministic(pk: &PublicKey, coins: &[u8; 32]) -> (Ciphertext, [u8; 32]) {
    let mut nonce_input = Vec::with_capacity(15 + 32 + 32);
    nonce_input.extend_from_slice(b"eirn-nonce");
    nonce_input.extend_from_slice(pk.as_bytes());
    nonce_input.extend_from_slice(coins);
    let nonce = sha3_256(&nonce_input);

    let mut mask_input = Vec::with_capacity(12 + 32 + 32);
    mask_input.extend_from_slice(b"eirn-fo-mask");
    mask_input.extend_from_slice(pk.as_bytes());
    mask_input.extend_from_slice(&nonce);
    let mask = shake256(&mask_input, 32);

    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&nonce);
    for (dst, (coin, mask_byte)) in data[32..].iter_mut().zip(coins.iter().zip(mask.iter())) {
        *dst = coin ^ mask_byte;
    }

    let mut ss_input = Vec::with_capacity(7 + 32 + 32);
    ss_input.extend_from_slice(b"eirn-ss");
    ss_input.extend_from_slice(pk.as_bytes());
    ss_input.extend_from_slice(coins);
    (
        Ciphertext {
            data,
            params: pk.params,
        },
        sha3_256(&ss_input),
    )
}

pub fn decaps(sk: &SecretKey, ct: &Ciphertext) -> [u8; 32] {
    let nonce = &ct.as_bytes()[..32];
    let encrypted = &ct.as_bytes()[32..];

    let mut mask_input = Vec::with_capacity(12 + 32 + 32);
    mask_input.extend_from_slice(b"eirn-fo-mask");
    mask_input.extend_from_slice(sk.public_key_bytes());
    mask_input.extend_from_slice(nonce);
    let mask = shake256(&mask_input, encrypted.len());

    let mut coins = [0u8; 32];
    for (dst, (cipher, mask_byte)) in coins.iter_mut().zip(encrypted.iter().zip(mask.iter())) {
        *dst = cipher ^ mask_byte;
    }

    let mut nonce_input = Vec::with_capacity(10 + 32 + 32);
    nonce_input.extend_from_slice(b"eirn-nonce");
    nonce_input.extend_from_slice(sk.public_key_bytes());
    nonce_input.extend_from_slice(&coins);
    let nonce_check = sha3_256(&nonce_input);

    if ct_eq(&nonce_check, nonce) {
        let mut ss_input = Vec::with_capacity(7 + 32 + 32);
        ss_input.extend_from_slice(b"eirn-ss");
        ss_input.extend_from_slice(sk.public_key_bytes());
        ss_input.extend_from_slice(&coins);
        sha3_256(&ss_input)
    } else {
        let mut reject_input = Vec::with_capacity(11 + 32 + 64);
        reject_input.extend_from_slice(b"eirn-reject");
        reject_input.extend_from_slice(sk.seed());
        reject_input.extend_from_slice(ct.as_bytes());
        sha3_256(&reject_input)
    }
}
