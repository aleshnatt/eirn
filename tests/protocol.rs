use eirn_kcp::{
    decaps, encaps, encaps_deterministic, generate_prekey_bundle, keygen, receiver_handshake,
    sender_handshake, KcpLiteProof, Msg0Prime, PublicKey,
};

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

    let proof = eirn_kcp::kcp_lite_prove(sk_a.seed(), pk_a.as_bytes(), &ctx).unwrap();
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

    let proof = eirn_kcp::kcp_lite_prove(sk_a.seed(), pk_a.as_bytes(), &ctx).unwrap();
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
fn handshake_produces_matching_session_keys() {
    let (pk_a, sk_a) = keygen();
    let mut bundle_b = generate_prekey_bundle(3);

    let (msg0, alice_ss) = sender_handshake(&sk_a, &pk_a, &bundle_b).unwrap();
    let bob_ss = receiver_handshake(&mut bundle_b, &msg0).unwrap();

    assert_eq!(alice_ss, bob_ss);
    assert_eq!(bundle_b.one_time_prekeys.len(), 2);
}

#[test]
fn msg0_prime_roundtrips_through_bytes() {
    let (pk_a, sk_a) = keygen();
    let mut bundle_b = generate_prekey_bundle(3);

    let (msg0, alice_ss) = sender_handshake(&sk_a, &pk_a, &bundle_b).unwrap();
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

    let (mut msg0, _) = sender_handshake(&sk_a, &pk_a, &bundle_b).unwrap();
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

    let err = eirn_kcp::kcp_lite_prove(sk_a.seed(), wrong_pk.as_bytes(), &ctx).unwrap_err();
    assert_eq!(err, eirn_kcp::EirnError::KeyMismatch);
}

#[test]
fn sender_handshake_rejects_mismatched_keypair() {
    let (_, sk_a) = keygen();
    let (wrong_pk, _) = keygen();
    let bundle_b = generate_prekey_bundle(3);

    let err = sender_handshake(&sk_a, &wrong_pk, &bundle_b).unwrap_err();
    assert_eq!(err, eirn_kcp::EirnError::KeyMismatch);
}

#[test]
fn debug_output_redacts_secret_material() {
    let (_, sk) = keygen();
    let sk_seed_hex = hex_lower(sk.seed());
    let sk_debug = format!("{sk:?}");
    assert!(sk_debug.contains("<redacted>"));
    assert!(!sk_debug.contains(&sk_seed_hex));

    let bundle = generate_prekey_bundle(2);
    let identity_seed_hex = hex_lower(bundle.identity_sk.seed());
    let signed_seed_hex = hex_lower(bundle.signed_prekey_sk.seed());
    let opk_seed_hex = hex_lower(bundle.one_time_prekeys[0].1.seed());
    let bundle_debug = format!("{bundle:?}");
    assert!(bundle_debug.contains("<redacted>"));
    assert!(!bundle_debug.contains(&identity_seed_hex));
    assert!(!bundle_debug.contains(&signed_seed_hex));
    assert!(!bundle_debug.contains(&opk_seed_hex));
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
