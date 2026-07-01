use crate::{
    error::{EirnError, Result},
    kem::{decaps, encaps, keygen, Ciphertext, PublicKey},
    naxos::{naxos_decaps, naxos_encaps},
    prekey::PrekeyBundle,
    session::derive_session_key,
    zk::{kcp_lite_prove_for_key, kcp_lite_verify, KcpLiteProof, KcpMode},
};

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
}

impl Msg0Prime {
    pub const SIZE: usize = 1 + PublicKey::SIZE * 2 + Ciphertext::SIZE * 4 + KcpLiteProof::SIZE;

    pub fn total_size(&self) -> usize {
        Self::SIZE
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0] = self.kcp_mode as u8;

        let mut offset = 1;
        write_field(&mut out, &mut offset, self.pk_a.as_bytes());
        write_field(&mut out, &mut offset, self.ek_a.as_bytes());
        write_field(&mut out, &mut offset, self.ct1.as_bytes());
        write_field(&mut out, &mut offset, self.ct2.as_bytes());
        write_field(&mut out, &mut offset, self.ct3.as_bytes());
        write_field(&mut out, &mut offset, self.ct4.as_bytes());
        write_field(&mut out, &mut offset, &self.kcp_lite_proof.to_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::from_bytes_with_params(data, crate::params::PARAMS_512)
    }

    pub fn from_bytes_with_params(data: &[u8], params: crate::params::EirnParams) -> Result<Self> {
        if data.len() != Self::SIZE {
            return Err(EirnError::InvalidMessageLength {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        if data[0] != KcpMode::Lite as u8 {
            return Err(EirnError::StrictModeUnavailable);
        }

        let mut offset = 1;
        let pk_a =
            PublicKey::from_bytes(read_field::<{ PublicKey::SIZE }>(data, &mut offset), params)?;
        let ek_a =
            PublicKey::from_bytes(read_field::<{ PublicKey::SIZE }>(data, &mut offset), params)?;
        let ct1 = Ciphertext::from_bytes(
            read_field::<{ Ciphertext::SIZE }>(data, &mut offset),
            params,
        )?;
        let ct2 = Ciphertext::from_bytes(
            read_field::<{ Ciphertext::SIZE }>(data, &mut offset),
            params,
        )?;
        let ct3 = Ciphertext::from_bytes(
            read_field::<{ Ciphertext::SIZE }>(data, &mut offset),
            params,
        )?;
        let ct4 = Ciphertext::from_bytes(
            read_field::<{ Ciphertext::SIZE }>(data, &mut offset),
            params,
        )?;
        let kcp_lite_proof =
            KcpLiteProof::from_bytes(read_field::<{ KcpLiteProof::SIZE }>(data, &mut offset))?;

        Ok(Self {
            pk_a,
            ek_a,
            ct1,
            ct2,
            ct3,
            ct4,
            kcp_mode: KcpMode::Lite,
            kcp_lite_proof,
        })
    }
}

pub fn build_context(pk_a: &PublicKey, pk_b: &PublicKey, ek_a: &PublicKey) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(96);
    ctx.extend_from_slice(pk_a.as_bytes());
    ctx.extend_from_slice(pk_b.as_bytes());
    ctx.extend_from_slice(ek_a.as_bytes());
    ctx
}

pub fn sender_handshake(
    sk_a: &crate::kem::SecretKey,
    pk_a: &PublicKey,
    bundle_b: &PrekeyBundle,
) -> Result<(Msg0Prime, [u8; 32])> {
    if !sk_a.matches_public_key(pk_a) {
        return Err(EirnError::KeyMismatch);
    }

    let (ek_a, esk_a) = keygen();
    let opk_b = bundle_b
        .one_time_prekeys
        .first()
        .ok_or(EirnError::NoOneTimePrekeys)?
        .0
        .clone();
    let ctx = build_context(pk_a, &bundle_b.identity_pk, &ek_a);

    let (ct1, k1) = encaps(&bundle_b.identity_pk);
    let (ct2, k2) = encaps(&bundle_b.signed_prekey_pk);
    let (ct3, k3) = encaps(&opk_b);
    let (ct4, k4) = naxos_encaps(&bundle_b.signed_prekey_pk, sk_a, &esk_a, &ctx);

    let proof = kcp_lite_prove_for_key(sk_a, pk_a, &ctx)?;
    let secrets = [k1, k2, k3, k4];
    let ciphertexts = [
        ct1.as_bytes().as_slice(),
        ct2.as_bytes().as_slice(),
        ct3.as_bytes().as_slice(),
        ct4.as_bytes().as_slice(),
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
            kcp_mode: KcpMode::Lite,
            kcp_lite_proof: proof,
        },
        ss,
    ))
}

fn write_field<const N: usize>(out: &mut [u8], offset: &mut usize, field: &[u8; N]) {
    out[*offset..*offset + N].copy_from_slice(field);
    *offset += N;
}

fn read_field<'a, const N: usize>(data: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let field = &data[*offset..*offset + N];
    *offset += N;
    field
}

pub fn receiver_handshake(bundle_b: &mut PrekeyBundle, msg0: &Msg0Prime) -> Result<[u8; 32]> {
    if msg0.kcp_mode != KcpMode::Lite {
        return Err(EirnError::StrictModeUnavailable);
    }

    let ctx = build_context(&msg0.pk_a, &bundle_b.identity_pk, &msg0.ek_a);
    if !kcp_lite_verify(msg0.pk_a.as_bytes(), &ctx, &msg0.kcp_lite_proof) {
        return Err(EirnError::AuthenticationFailed);
    }

    let (_, opk_sk) = bundle_b.consume_opk()?;
    let k1 = decaps(&bundle_b.identity_sk, &msg0.ct1);
    let k2 = decaps(&bundle_b.signed_prekey_sk, &msg0.ct2);
    let k3 = decaps(&opk_sk, &msg0.ct3);
    let k4 = naxos_decaps(&bundle_b.signed_prekey_sk, &msg0.ct4, &msg0.pk_a, &ctx);

    let secrets = [k1, k2, k3, k4];
    let ciphertexts = [
        msg0.ct1.as_bytes().as_slice(),
        msg0.ct2.as_bytes().as_slice(),
        msg0.ct3.as_bytes().as_slice(),
        msg0.ct4.as_bytes().as_slice(),
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
