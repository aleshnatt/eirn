//! Hash-based KEM-like building blocks for Eirn-KCP.
//!
//! This module implements fixed-size key generation, encapsulation, and
//! decapsulation used by the handshake. It is designed to bind ciphertexts to a
//! recipient public key and return deterministic rejection secrets for malformed
//! ciphertexts. It does not implement a standardized post-quantum KEM, and its
//! side-channel and reduction properties require independent review.

use core::fmt;

use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroize;

use crate::{
    error::{EirnError, Result},
    params::{EirnParams, PARAMS_512},
    util::{ct_eq, sha3_256, shake256},
};

/// Public encapsulation key for an Eirn-KCP profile.
///
/// The key identifies the recipient in KEM and handshake transcripts. Equality
/// and byte conversion preserve the attached parameter profile so callers can
/// avoid mixing incompatible protocol profiles. Callers must obtain public keys
/// from authenticated bundle metadata before trusting a derived session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    data: [u8; 32],
    params: EirnParams,
}

impl PublicKey {
    /// Fixed encoded public-key size in bytes.
    pub const SIZE: usize = 32;

    /// Returns the canonical fixed-size public-key encoding.
    ///
    /// # Security
    ///
    /// The returned bytes identify the key in transcript binding. Callers must
    /// authenticate the source of these bytes before using them as a peer
    /// identity.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }

    /// Parses a public key from its fixed-size byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`EirnError::InvalidKeyLength`] if `data` is not exactly
    /// [`PublicKey::SIZE`] bytes.
    ///
    /// # Untrusted Input
    ///
    /// This function accepts data from untrusted sources. All structural checks
    /// are performed before any arithmetic. Malformed input is rejected with an
    /// error rather than panicking.
    ///
    /// # Security
    ///
    /// Parsing does not authenticate the key. Callers must bind the returned key
    /// to an authenticated identity or trusted prekey bundle.
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

    /// Returns the protocol profile attached to this key.
    ///
    /// # Security
    ///
    /// Parameter equality is used to prevent accidental cross-profile use.
    /// Callers must still choose profiles appropriate for their deployment.
    pub fn params(&self) -> EirnParams {
        self.params
    }
}

/// Secret encapsulation key for an Eirn-KCP profile.
///
/// The key owns the seed used for decapsulation and KCP-Lite proof generation.
/// Its debug representation redacts the seed, and the seed is zeroized on drop.
/// Callers must keep values of this type private and avoid cloning them beyond
/// the lifetime needed for a handshake.
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
    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Returns the public key bytes derived from this secret key.
    ///
    /// # Security
    ///
    /// These bytes are safe to publish, but callers must not treat publication
    /// as proof that the peer controls the secret key. Use KCP-Lite proof
    /// verification or authenticated bundle metadata for that binding.
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.pk_data
    }

    /// Returns the protocol profile attached to this key.
    ///
    /// # Security
    ///
    /// Parameter equality helps reject accidental profile mixing. It does not
    /// validate that the profile is strong enough for a deployment.
    pub fn params(&self) -> EirnParams {
        self.params
    }

    /// Checks whether this secret key owns the supplied public key.
    ///
    /// # Timing
    ///
    /// The byte comparison is performed with `subtle` constant-time equality.
    ///
    /// # Security
    ///
    /// A `true` result only proves local key-pair consistency. Callers must not
    /// use it as peer authentication.
    pub fn matches_public_key(&self, pk: &PublicKey) -> bool {
        self.params == pk.params && ct_eq(&self.pk_data, pk.as_bytes())
    }
}

/// Fixed-size encapsulation ciphertext.
///
/// The ciphertext carries the nonce and masked coins needed by the recipient to
/// derive the same shared secret. Decapsulation uses deterministic rejection
/// when the nonce check fails. Callers must include ciphertext bytes in the
/// session transcript so substitution changes the derived session key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    data: [u8; 64],
    params: EirnParams,
}

impl Ciphertext {
    /// Fixed encoded ciphertext size in bytes.
    pub const SIZE: usize = 64;

    /// Returns the canonical fixed-size ciphertext encoding.
    ///
    /// # Security
    ///
    /// These bytes must be transcript-bound by higher-level protocols. A
    /// ciphertext alone does not authenticate the sender.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.data
    }

    /// Parses a ciphertext from its fixed-size byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`EirnError::InvalidCiphertextLength`] if `data` is not exactly
    /// [`Ciphertext::SIZE`] bytes.
    ///
    /// # Untrusted Input
    ///
    /// This function accepts data from untrusted sources. All structural checks
    /// are performed before any arithmetic. Malformed input is rejected with an
    /// error rather than panicking.
    ///
    /// # Security
    ///
    /// Parsing does not validate that the ciphertext was produced for a
    /// particular recipient. Callers must decapsulate with the intended secret
    /// key and bind the ciphertext bytes into the transcript.
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

    /// Returns the protocol profile attached to this ciphertext.
    ///
    /// # Security
    ///
    /// Callers should reject profile mismatches before combining ciphertexts
    /// with keys from a different profile.
    pub fn params(&self) -> EirnParams {
        self.params
    }
}

/// Generates a key pair under the default Eirn-512 profile.
///
/// # Randomness
///
/// This function uses `OsRng` as a cryptographically secure pseudorandom number
/// generator. A platform RNG failure will abort inside the RNG provider.
pub fn keygen() -> (PublicKey, SecretKey) {
    keygen_with_rng(&mut OsRng, PARAMS_512)
}

/// Generates a key pair under `params` using the operating-system RNG.
///
/// # Randomness
///
/// This function uses `OsRng` as a cryptographically secure pseudorandom number
/// generator. A platform RNG failure will abort inside the RNG provider.
///
/// # Security
///
/// The selected parameters are stored with both keys. Callers must choose a
/// profile that matches every peer and ciphertext in the protocol run.
pub fn keygen_with_params(params: EirnParams) -> (PublicKey, SecretKey) {
    keygen_with_rng(&mut OsRng, params)
}

/// Generates a key pair under `params` using caller-supplied randomness.
///
/// # Randomness
///
/// The `rng` parameter must be a cryptographically secure pseudorandom number
/// generator. Passing a weak or deterministic RNG breaks the security of the
/// output.
///
/// # Security
///
/// The generated secret key seed must remain private. Test-only deterministic
/// RNGs must never be used for real protocol keys.
pub fn keygen_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: EirnParams,
) -> (PublicKey, SecretKey) {
    let mut secret_seed = [0u8; 32];
    rng.fill_bytes(&mut secret_seed);
    keygen_from_seed(secret_seed, params)
}

/// Derives a key pair deterministically from a 32-byte seed.
///
/// # Security
///
/// This constructor is intended for tests and deterministic fixtures. Reusing a
/// seed or deriving it from low-entropy input gives every holder of the seed the
/// secret key.
pub fn keygen_from_seed(seed: [u8; 32], params: EirnParams) -> (PublicKey, SecretKey) {
    let signing_key = SigningKey::from_bytes(&seed);
    let pk_data = signing_key.verifying_key().to_bytes();
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

/// Encapsulates to `pk` using `OsRng`.
///
/// # Randomness
///
/// This function uses `OsRng` as a cryptographically secure pseudorandom number
/// generator. Fresh coins are required for each encapsulation.
///
/// # Security
///
/// The returned shared secret must be fed into a transcript-bound KDF before it
/// is used as an application key.
pub fn encaps(pk: &PublicKey) -> (Ciphertext, [u8; 32]) {
    encaps_with_rng(&mut OsRng, pk)
}

/// Encapsulates to `pk` using caller-supplied randomness.
///
/// # Randomness
///
/// The `rng` parameter must be a cryptographically secure pseudorandom number
/// generator. Passing a weak or deterministic RNG breaks the security of the
/// output.
///
/// # Security
///
/// The returned shared secret is bound to the recipient public key and random
/// coins, not to a full handshake transcript. Higher-level code must bind peer
/// identities and ciphertext bytes before deriving session keys.
pub fn encaps_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
) -> (Ciphertext, [u8; 32]) {
    let mut encapsulation_coins = [0u8; 32];
    rng.fill_bytes(&mut encapsulation_coins);
    encaps_deterministic(pk, &encapsulation_coins)
}

/// Encapsulates to `pk` with explicit 32-byte coins.
///
/// # Security
///
/// This function is deterministic and should be used only when the coins are
/// already cryptographically random or intentionally derived by a protocol such
/// as the NAXOS path. Reusing coins for the same recipient repeats the
/// ciphertext and shared secret.
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

/// Decapsulates a ciphertext or returns a deterministic rejection secret.
///
/// # Security
///
/// Valid ciphertexts produce the sender's shared secret. Invalid ciphertexts
/// produce a deterministic rejection secret keyed by the recipient secret seed,
/// so callers must not reveal which branch occurred through protocol behavior.
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
