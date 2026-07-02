//! Sender and receiver handshake orchestration for Eirn-KCP.
//!
//! This module constructs and consumes the initial `MSG0'` message. It is
//! designed to resist replay and key-substitution attacks when prekey bundles
//! are authenticated and one-time prekeys are consumed exactly once. It does not
//! protect against maliciously supplied receiver bundles or side channels in the
//! surrounding application.

use crate::{
    error::{EirnError, Result},
    kem::{decaps, encaps, Ciphertext, PublicKey},
    naxos::{naxos_decaps, naxos_encaps},
    prekey::{PrekeyBundle, PublicPrekeyBundle},
    session::derive_session_key,
    zk::{
        kcp_lite_prove_for_key, kcp_lite_verify, kcp_strict_prove, kcp_strict_verify, KcpLiteProof,
        KcpMode, KcpStrictProof,
    },
};

/// Initial sender message for the asynchronous Eirn-KCP handshake.
///
/// The message carries the sender identity key, sender ephemeral key, four
/// ciphertexts with distinct binding roles, and either a KCP-Lite or KCP-Strict
/// proof tying the sender identity to the session context. Verifying the
/// message authenticates the sender only if the sender public key is expected
/// by the caller. Callers must reject unauthenticated receiver bundles and must
/// not reuse consumed one-time prekeys.
#[derive(Clone, Debug)]
pub struct Msg0Prime {
    pub pk_a: PublicKey,
    pub ek_a: PublicKey,
    pub ct1: Ciphertext,
    pub ct2: Ciphertext,
    pub ct3: Ciphertext,
    pub ct4: Ciphertext,
    pub kcp_mode: KcpMode,
    pub kcp_lite_proof: KcpLiteProof,
    pub kcp_strict_proof: Option<KcpStrictProof>,
}

impl Msg0Prime {
    /// Fixed encoded `MSG0'` size in bytes for the default profile.
    pub const SIZE: usize = 1 + PublicKey::SIZE * 2 + Ciphertext::SIZE * 4 + KcpLiteProof::SIZE;

    /// Returns the fixed encoded size for this message.
    ///
    /// # Security
    ///
    /// The size is structural metadata only. Callers must still verify the
    /// selected proof mode and derive the session key before accepting a
    /// message.
    pub fn total_size(&self) -> usize {
        msg0_size(self.pk_a.params(), self.kcp_mode)
    }

    /// Serializes the message to its fixed-size wire encoding.
    ///
    /// # Security
    ///
    /// Serialization does not authenticate the message. Receivers must run
    /// [`receiver_handshake`] or equivalent proof verification before using
    /// derived keys.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.total_size());
        out.push(self.kcp_mode as u8);

        write_field(&mut out, self.pk_a.as_bytes());
        write_field(&mut out, self.ek_a.as_bytes());
        write_field(&mut out, self.ct1.as_bytes());
        write_field(&mut out, self.ct2.as_bytes());
        write_field(&mut out, self.ct3.as_bytes());
        write_field(&mut out, self.ct4.as_bytes());
        match self.kcp_mode {
            KcpMode::Lite => write_field(&mut out, &self.kcp_lite_proof.to_bytes()),
            KcpMode::Strict => {
                let proof = self
                    .kcp_strict_proof
                    .as_ref()
                    .expect("strict messages carry a strict proof");
                write_field(&mut out, &proof.to_bytes());
            }
        }
        out
    }

    /// Parses a default-profile message from its fixed-size wire encoding.
    ///
    /// # Errors
    ///
    /// Returns [`EirnError::InvalidMessageLength`] if `data` has the wrong
    /// length, [`EirnError::StrictModeUnavailable`] if the mode byte is
    /// unknown, or a key, ciphertext, or proof length error if a field fails
    /// structural parsing.
    ///
    /// # Untrusted Input
    ///
    /// This function accepts data from untrusted sources. All structural checks
    /// are performed before any arithmetic. Malformed input is rejected with an
    /// error rather than panicking.
    ///
    /// # Security
    ///
    /// Parsing does not verify the sender proof or consume a one-time prekey.
    /// Callers must pass the result to [`receiver_handshake`] before accepting
    /// the transcript.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::from_bytes_with_params(data, crate::params::PARAMS_768)
    }

    /// Parses a message from its fixed-size wire encoding under `params`.
    ///
    /// # Errors
    ///
    /// Returns [`EirnError::InvalidMessageLength`] if `data` has the wrong
    /// length, [`EirnError::StrictModeUnavailable`] if the mode byte is
    /// unknown, or a key, ciphertext, or proof length error if a field fails
    /// structural parsing.
    ///
    /// # Untrusted Input
    ///
    /// This function accepts data from untrusted sources. All structural checks
    /// are performed before any arithmetic. Malformed input is rejected with an
    /// error rather than panicking.
    ///
    /// # Security
    ///
    /// The caller must supply the same parameter profile expected for the peer
    /// bundle. Successful parsing is not proof verification.
    pub fn from_bytes_with_params(data: &[u8], params: crate::params::EirnParams) -> Result<Self> {
        let mode = match data.first().copied() {
            Some(byte) if byte == KcpMode::Lite as u8 => KcpMode::Lite,
            Some(byte) if byte == KcpMode::Strict as u8 => KcpMode::Strict,
            Some(_) => return Err(EirnError::StrictModeUnavailable),
            None => {
                return Err(EirnError::InvalidMessageLength {
                    expected: 1,
                    actual: 0,
                })
            }
        };
        let expected_size = msg0_size(params, mode);
        if data.len() != expected_size {
            return Err(EirnError::InvalidMessageLength {
                expected: expected_size,
                actual: data.len(),
            });
        }

        let mut offset = 1;
        let pk_a = PublicKey::from_bytes(
            read_dynamic_field(data, &mut offset, params.pk_bytes),
            params,
        )?;
        let ek_a = PublicKey::from_bytes(
            read_dynamic_field(data, &mut offset, params.pk_bytes),
            params,
        )?;
        let ct1 = Ciphertext::from_bytes(
            read_dynamic_field(data, &mut offset, params.ct_bytes),
            params,
        )?;
        let ct2 = Ciphertext::from_bytes(
            read_dynamic_field(data, &mut offset, params.ct_bytes),
            params,
        )?;
        let ct3 = Ciphertext::from_bytes(
            read_dynamic_field(data, &mut offset, params.ct_bytes),
            params,
        )?;
        let ct4 = Ciphertext::from_bytes(
            read_dynamic_field(data, &mut offset, params.ct_bytes),
            params,
        )?;
        let (kcp_lite_proof, kcp_strict_proof) = match mode {
            KcpMode::Lite => (
                KcpLiteProof::from_bytes_with_params(
                    read_dynamic_field(data, &mut offset, params.proof_bytes),
                    params,
                )?,
                None,
            ),
            KcpMode::Strict => (
                empty_lite_proof(params),
                Some(KcpStrictProof::from_bytes(read_dynamic_field(
                    data,
                    &mut offset,
                    params.strict_proof_bytes,
                ))?),
            ),
        };

        Ok(Self {
            pk_a,
            ek_a,
            ct1,
            ct2,
            ct3,
            ct4,
            kcp_mode: mode,
            kcp_lite_proof,
            kcp_strict_proof,
        })
    }
}

/// Builds the KCP session context from sender, receiver, and ephemeral keys.
///
/// # Security
///
/// The context is only meaningful when `pk_b` is the authenticated receiver
/// identity key and `ek_a` is fresh for the session. Reusing `ek_a` weakens
/// replay separation across handshakes.
pub fn build_context(pk_a: &PublicKey, pk_b: &PublicKey, ek_a: &PublicKey) -> Vec<u8> {
    let mut ctx =
        Vec::with_capacity(pk_a.as_bytes().len() + pk_b.as_bytes().len() + ek_a.as_bytes().len());
    ctx.extend_from_slice(pk_a.as_bytes());
    ctx.extend_from_slice(pk_b.as_bytes());
    ctx.extend_from_slice(ek_a.as_bytes());
    ctx
}

/// Creates the sender's initial message and transcript-bound session key.
///
/// # Errors
///
/// Returns [`EirnError::KeyMismatch`] if `sk_a` does not own `pk_a`.
/// Returns [`EirnError::NoOneTimePrekeys`] if `bundle_b` has no public one-time
/// prekey. Returns [`EirnError::KeyMismatch`] from proof generation if the key
/// relationship fails during proof construction.
///
/// # Security
///
/// `bundle_b` must be authenticated as the receiver's current public prekey
/// bundle. The function consumes no receiver state because it only sees the
/// public half; receivers must enforce one-time prekey consumption when they
/// process the message.
pub fn sender_handshake(
    sk_a: &crate::kem::SecretKey,
    pk_a: &PublicKey,
    bundle_b: &PublicPrekeyBundle,
) -> Result<(Msg0Prime, [u8; 32])> {
    sender_handshake_with_mode(sk_a, pk_a, bundle_b, KcpMode::Lite)
}

/// Creates the sender's initial message with a KCP-Strict lattice-native proof.
pub fn sender_handshake_strict(
    sk_a: &crate::kem::SecretKey,
    pk_a: &PublicKey,
    bundle_b: &PublicPrekeyBundle,
) -> Result<(Msg0Prime, [u8; 32])> {
    sender_handshake_with_mode(sk_a, pk_a, bundle_b, KcpMode::Strict)
}

fn sender_handshake_with_mode(
    sk_a: &crate::kem::SecretKey,
    pk_a: &PublicKey,
    bundle_b: &PublicPrekeyBundle,
    mode: KcpMode,
) -> Result<(Msg0Prime, [u8; 32])> {
    if !sk_a.matches_public_key(pk_a) {
        return Err(EirnError::KeyMismatch);
    }

    let params = bundle_b.identity_pk.params();
    if pk_a.params() != params || bundle_b.signed_prekey_pk.params() != params {
        return Err(EirnError::KeyMismatch);
    }

    let (ek_a, esk_a) = crate::kem::keygen_with_params(params);
    let opk_b = bundle_b
        .one_time_prekeys
        .first()
        .ok_or(EirnError::NoOneTimePrekeys)?
        .clone();
    if opk_b.params() != params {
        return Err(EirnError::KeyMismatch);
    }
    let ctx = build_context(pk_a, &bundle_b.identity_pk, &ek_a);

    // ct1 binds the session to the receiver identity key.
    let (ct1, k1) = encaps(&bundle_b.identity_pk);
    // ct2 binds the session to the receiver signed prekey.
    let (ct2, k2) = encaps(&bundle_b.signed_prekey_pk);
    // ct3 consumes a one-time prekey for replay separation.
    let (ct3, k3) = encaps(&opk_b);
    // ct4 adds NAXOS-style sender identity and ephemeral entropy.
    let (ct4, k4) = naxos_encaps(&bundle_b.signed_prekey_pk, sk_a, &esk_a, &ctx);

    let (kcp_lite_proof, kcp_strict_proof) = match mode {
        KcpMode::Lite => (kcp_lite_prove_for_key(sk_a, pk_a, &ctx)?, None),
        KcpMode::Strict => (
            empty_lite_proof(params),
            Some(kcp_strict_prove(sk_a, pk_a, &ctx)?),
        ),
    };
    let secrets = [k1, k2, k3, k4];
    let ciphertexts = [
        ct1.as_bytes(),
        ct2.as_bytes(),
        ct3.as_bytes(),
        ct4.as_bytes(),
    ];
    let ss = derive_session_key(
        &secrets,
        pk_a.as_bytes(),
        bundle_b.identity_pk.as_bytes(),
        ek_a.as_bytes(),
        &ciphertexts,
        None,
    );

    Ok((
        Msg0Prime {
            pk_a: pk_a.clone(),
            ek_a,
            ct1,
            ct2,
            ct3,
            ct4,
            kcp_mode: mode,
            kcp_lite_proof,
            kcp_strict_proof,
        },
        ss,
    ))
}

fn write_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(field);
}

fn read_dynamic_field<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> &'a [u8] {
    let field = &data[*offset..*offset + len];
    *offset += len;
    field
}

fn msg0_size(params: crate::params::EirnParams, mode: KcpMode) -> usize {
    let proof_size = match mode {
        KcpMode::Lite => params.proof_bytes,
        KcpMode::Strict => params.strict_proof_bytes,
    };
    1 + params.pk_bytes * 2 + params.ct_bytes * 4 + proof_size
}

fn empty_lite_proof(params: crate::params::EirnParams) -> KcpLiteProof {
    KcpLiteProof {
        commitment: [0u8; 32],
        response: vec![0u8; params.sig_bytes],
        anchor: [0u8; 32],
    }
}

/// Verifies `msg0`, consumes one one-time prekey, and derives the receiver key.
///
/// # Errors
///
/// Returns [`EirnError::AuthenticationFailed`] if the selected proof fails, or
/// [`EirnError::NoOneTimePrekeys`] if receiver state has no one-time prekey left
/// to consume.
///
/// # Security
///
/// The receiver bundle must belong to the intended recipient and must not be
/// reused after its one-time prekey pool is depleted. A returned key is valid
/// only for the transcript represented by `msg0`.
pub fn receiver_handshake(bundle_b: &mut PrekeyBundle, msg0: &Msg0Prime) -> Result<[u8; 32]> {
    let params = bundle_b.identity_pk.params();
    if msg0.pk_a.params() != params
        || msg0.ek_a.params() != params
        || msg0.ct1.params() != params
        || msg0.ct2.params() != params
        || msg0.ct3.params() != params
        || msg0.ct4.params() != params
    {
        return Err(EirnError::KeyMismatch);
    }

    let ctx = build_context(&msg0.pk_a, &bundle_b.identity_pk, &msg0.ek_a);
    match msg0.kcp_mode {
        KcpMode::Lite => {
            if !kcp_lite_verify(msg0.pk_a.as_bytes(), &ctx, &msg0.kcp_lite_proof) {
                return Err(EirnError::AuthenticationFailed);
            }
        }
        KcpMode::Strict => {
            let proof = msg0
                .kcp_strict_proof
                .as_ref()
                .ok_or(EirnError::AuthenticationFailed)?;
            if !kcp_strict_verify(&msg0.pk_a, &ctx, proof) {
                return Err(EirnError::AuthenticationFailed);
            }
        }
    }

    let (_, opk_sk) = bundle_b.consume_opk()?;
    let k1 = decaps(bundle_b.identity_sk(), &msg0.ct1);
    let k2 = decaps(bundle_b.signed_prekey_sk(), &msg0.ct2);
    let k3 = decaps(&opk_sk, &msg0.ct3);
    let k4 = naxos_decaps(bundle_b.signed_prekey_sk(), &msg0.ct4, &msg0.pk_a, &ctx);

    let secrets = [k1, k2, k3, k4];
    let ciphertexts = [
        msg0.ct1.as_bytes(),
        msg0.ct2.as_bytes(),
        msg0.ct3.as_bytes(),
        msg0.ct4.as_bytes(),
    ];
    Ok(derive_session_key(
        &secrets,
        msg0.pk_a.as_bytes(),
        bundle_b.identity_pk.as_bytes(),
        msg0.ek_a.as_bytes(),
        &ciphertexts,
        None,
    ))
}
