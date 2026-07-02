use eirn_kcp::{
    decaps, encaps, encaps_deterministic, generate_prekey_bundle, keygen, receiver_handshake,
    sender_handshake, KcpLiteProof, Msg0Prime, PublicKey,
};
use sha3::{Digest, Sha3_256};

#[test]
fn kem_roundtrip_matches() {
    let (pk, sk) = keygen();
    let (ct, ss_enc) = encaps(&pk);
    let ss_dec = decaps(&sk, &ct);
    assert_eq!(ss_enc, ss_dec);
}

#[test]
fn kem_wrong_key_rejects() {
    let (pk, _) = keygen();
    let (_, wrong_sk) = keygen();
    let (ct, ss_enc) = encaps(&pk);
    let ss_wrong = decaps(&wrong_sk, &ct);
    assert_ne!(ss_enc, ss_wrong);
}

#[test]
fn deterministic_encapsulation_is_stable() {
    let (pk, _) = keygen();
    let coins = [7u8; 32];
    let (ct1, ss1) = encaps_deterministic(&pk, &coins);
    let (ct2, ss2) = encaps_deterministic(&pk, &coins);
    assert_eq!(ct1.as_bytes(), ct2.as_bytes());
    assert_eq!(ss1, ss2);
}

#[test]
fn kcp_lite_proof_roundtrips_and_verifies() {
    let (pk_a, sk_a) = keygen();
    let (pk_b, _) = keygen();
    let (ek_a, _) = keygen();
    let ctx = eirn_kcp::build_context(&pk_a, &pk_b, &ek_a);

    let proof = eirn_kcp::kcp_lite_prove(&sk_a, pk_a.as_bytes(), &ctx).unwrap();
    assert!(eirn_kcp::kcp_lite_verify(pk_a.as_bytes(), &ctx, &proof));

    let encoded = proof.to_bytes();
    let decoded = KcpLiteProof::from_bytes(&encoded).unwrap();
    assert_eq!(proof, decoded);
}

#[test]
fn public_key_roundtrips_from_bytes() {
    let (pk, _) = keygen();
    let decoded = PublicKey::from_bytes(pk.as_bytes(), pk.params()).unwrap();

    assert_eq!(decoded, pk);
}

#[test]
fn kcp_lite_rejects_tampering_and_replay() {
    let (pk_a, sk_a) = keygen();
    let (pk_b, _) = keygen();
    let (ek_a, _) = keygen();
    let (ek_other, _) = keygen();
    let ctx = eirn_kcp::build_context(&pk_a, &pk_b, &ek_a);
    let other_ctx = eirn_kcp::build_context(&pk_a, &pk_b, &ek_other);

    let proof = eirn_kcp::kcp_lite_prove(&sk_a, pk_a.as_bytes(), &ctx).unwrap();
    assert!(!eirn_kcp::kcp_lite_verify(
        pk_a.as_bytes(),
        &other_ctx,
        &proof
    ));

    let mut tampered = proof.clone();
    tampered.response[0] ^= 1;
    assert!(!eirn_kcp::kcp_lite_verify(pk_a.as_bytes(), &ctx, &tampered));
}

#[test]
fn kcp_lite_proof_can_be_created_without_exposing_seed() {
    let (pk_a, sk_a) = keygen();
    let (pk_b, _) = keygen();
    let (ek_a, _) = keygen();
    let ctx = eirn_kcp::build_context(&pk_a, &pk_b, &ek_a);

    let proof = eirn_kcp::kcp_lite_prove_for_key(&sk_a, &pk_a, &ctx).unwrap();

    assert!(eirn_kcp::kcp_lite_verify(pk_a.as_bytes(), &ctx, &proof));
}

#[test]
fn kcp_lite_rejects_forged_proof() {
    let (pk_a, sk_a) = keygen();
    let (pk_b, _) = keygen();
    let (ek_a, _) = keygen();
    let ctx = eirn_kcp::build_context(&pk_a, &pk_b, &ek_a);

    let mut forged = eirn_kcp::kcp_lite_prove(&sk_a, pk_a.as_bytes(), &ctx).unwrap();
    // invalid signature bytes with a recomputed anchor
    forged.response = [9u8; 64];
    forged.anchor = kcp_lite_anchor(pk_a.as_bytes(), &forged.response, &ctx);

    assert!(!eirn_kcp::kcp_lite_verify(pk_a.as_bytes(), &ctx, &forged));
}

#[test]
fn kcp_lite_rejects_wrong_context() {
    let (pk_a, sk_a) = keygen();
    let (pk_b, _) = keygen();
    let (ek_a, _) = keygen();
    let (ek_other, _) = keygen();
    let ctx = eirn_kcp::build_context(&pk_a, &pk_b, &ek_a);
    let other_ctx = eirn_kcp::build_context(&pk_a, &pk_b, &ek_other);

    let proof = eirn_kcp::kcp_lite_prove(&sk_a, pk_a.as_bytes(), &ctx).unwrap();

    assert!(!eirn_kcp::kcp_lite_verify(
        pk_a.as_bytes(),
        &other_ctx,
        &proof
    ));
}

#[test]
fn handshake_produces_matching_session_keys() {
    let (pk_a, sk_a) = keygen();
    let mut bundle_b = generate_prekey_bundle(3);
    let public_bundle_b = bundle_b.public_bundle();

    let (msg0, alice_ss) = sender_handshake(&sk_a, &pk_a, &public_bundle_b).unwrap();
    let bob_ss = receiver_handshake(&mut bundle_b, &msg0).unwrap();

    assert_eq!(alice_ss, bob_ss);
    assert_eq!(bundle_b.one_time_prekeys.len(), 2);
}

#[test]
fn msg0_prime_roundtrips_through_bytes() {
    let (pk_a, sk_a) = keygen();
    let mut bundle_b = generate_prekey_bundle(3);
    let public_bundle_b = bundle_b.public_bundle();

    let (msg0, alice_ss) = sender_handshake(&sk_a, &pk_a, &public_bundle_b).unwrap();
    let encoded = msg0.to_bytes();
    assert_eq!(encoded.len(), Msg0Prime::SIZE);

    let decoded = Msg0Prime::from_bytes(&encoded).unwrap();
    assert_eq!(decoded.total_size(), Msg0Prime::SIZE);
    assert_eq!(decoded.to_bytes(), encoded);

    let bob_ss = receiver_handshake(&mut bundle_b, &decoded).unwrap();
    assert_eq!(alice_ss, bob_ss);
}

#[test]
fn handshake_rejects_tampered_proof() {
    let (pk_a, sk_a) = keygen();
    let mut bundle_b = generate_prekey_bundle(3);
    let public_bundle_b = bundle_b.public_bundle();

    let (mut msg0, _) = sender_handshake(&sk_a, &pk_a, &public_bundle_b).unwrap();
    msg0.kcp_lite_proof.anchor[0] ^= 1;

    let err = receiver_handshake(&mut bundle_b, &msg0).unwrap_err();
    assert_eq!(err, eirn_kcp::EirnError::AuthenticationFailed);
}

#[test]
fn proof_generation_rejects_mismatched_public_key() {
    let (_, sk_a) = keygen();
    let (wrong_pk, _) = keygen();
    let (pk_b, _) = keygen();
    let (ek_a, _) = keygen();
    let ctx = eirn_kcp::build_context(&wrong_pk, &pk_b, &ek_a);

    let err = eirn_kcp::kcp_lite_prove(&sk_a, wrong_pk.as_bytes(), &ctx).unwrap_err();
    assert_eq!(err, eirn_kcp::EirnError::KeyMismatch);
}

#[test]
fn sender_handshake_rejects_mismatched_keypair() {
    let (_, sk_a) = keygen();
    let (wrong_pk, _) = keygen();
    let bundle_b = generate_prekey_bundle(3);
    let public_bundle_b = bundle_b.public_bundle();

    let err = sender_handshake(&sk_a, &wrong_pk, &public_bundle_b).unwrap_err();
    assert_eq!(err, eirn_kcp::EirnError::KeyMismatch);
}

#[test]
fn handshake_uses_public_bundle_only() {
    let (pk_a, sk_a) = keygen();
    let mut bundle_b = generate_prekey_bundle(3);
    let public_bundle_b = bundle_b.public_bundle();

    let (msg0, alice_ss) = sender_handshake(&sk_a, &pk_a, &public_bundle_b).unwrap();
    let bob_ss = receiver_handshake(&mut bundle_b, &msg0).unwrap();

    assert_eq!(alice_ss, bob_ss);
}

#[test]
fn debug_output_redacts_secret_material() {
    let (_, sk) = keygen();
    let sk_debug = format!("{sk:?}");
    assert!(sk_debug.contains("<redacted>"));

    let bundle = generate_prekey_bundle(2);
    let bundle_debug = format!("{bundle:?}");
    assert!(bundle_debug.contains("<redacted>"));
}

fn kcp_lite_anchor(pk: &[u8; 32], response: &[u8; 64], ctx: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"eirn-kcp-lite-anchor-v1");
    hasher.update(pk);
    hasher.update(response);
    hasher.update(ctx);
    hasher.finalize().into()
}
