"""
Tests for MITM Attack Resistance.

Simulates Man-in-the-Middle attacks against Eirn-ZK:

1. Key Substitution Attack:
   - Mallory replaces pk_A with pk_M in MSG0'
   - Cannot forge valid ZK proof for pk_A (doesn't know sk_A)
   - Cannot create valid ZK proof for pk_M binding to Alice's context

2. Malicious Directory Server:
   - Server replaces pk_A in directory with pk_M
   - Bob receives pk_M but Alice generates proof for pk_A
   - ZK proof fails because anchor doesn't match pk_M

3. Proof Stripping Attack:
   - Mallory removes ZK proof from MSG0'
   - Protocol should detect missing/invalid proof

4. Ciphertext Manipulation:
   - Mallory modifies ciphertexts in MSG0'
   - Session key derivation fails (different root keys)
"""

import pytest
from eirn_kem.kem import KeyGen
from eirn_kem.utils import random_bytes, concat
from protocol.prekey import generate_prekey_bundle
from protocol.handshake import (
    sender_handshake, receiver_handshake,
    MSG0Prime, AuthenticationError, build_context
)
from zk.sigma import prove, verify, ZKProof


class TestKeySubstitutionAttack:
    """
    MITM: Mallory intercepts MSG0' and replaces pk_A with pk_M.
    
    Attack model:
      Alice → [MSG0' with pk_A, zk_proof] → Mallory → [modified msg] → Bob
    
    Mallory wants Bob to think the message came from Mallory (pk_M)
    but cannot forge a ZK proof for pk_A (doesn't know sk_A).
    """
    
    def test_cannot_forge_proof_for_alice(self):
        """Mallory cannot create a valid ZK proof for Alice's pk_A."""
        # Alice's keys
        pk_A, sk_A = KeyGen()
        
        # Mallory's keys
        pk_M, sk_M = KeyGen()
        
        # Context (from Alice's perspective)
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        # Mallory tries to forge proof for pk_A using sk_M
        forged_proof = prove(bytes(sk_M), bytes(pk_A), ctx)
        
        # The proof is structurally valid but the anchor is wrong
        # Full verification with the correct sk_A should fail
        from zk.sigma import _verify_with_secret
        assert not _verify_with_secret(bytes(sk_A), bytes(pk_A), ctx, forged_proof), (
            "MITM: Mallory forged a proof for Alice's pk_A — CRITICAL FAILURE"
        )
    
    def test_cannot_rebind_proof_to_pk_M(self):
        """
        Mallory cannot take Alice's valid proof and make it verify
        under pk_M instead of pk_A.
        """
        pk_A, sk_A = KeyGen()
        pk_M, sk_M = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        
        ctx_A = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        ctx_M = concat(bytes(pk_M), bytes(pk_B), bytes(ek_A))
        
        # Alice generates valid proof
        alice_proof = prove(bytes(sk_A), bytes(pk_A), ctx_A)
        
        # Mallory tries to verify Alice's proof under pk_M
        assert not verify(bytes(pk_M), ctx_A, alice_proof), (
            "MITM: Alice's proof verified under Mallory's pk_M"
        )
        
        # Also try with Mallory's context
        assert not verify(bytes(pk_M), ctx_M, alice_proof), (
            "MITM: Alice's proof verified under Mallory's context"
        )


class TestMaliciousDirectory:
    """
    Attack: Malicious directory server replaces pk_A with pk_M.
    
    Scenario:
      1. Alice uploads pk_A to directory
      2. Malicious server replaces it with pk_M (Mallory's key)
      3. When Alice sends MSG0', her ZK proof proves knowledge of sk_A
      4. Bob receives MSG0' with zk_proof for pk_A
      5. If Bob looks up pk_A from directory, he gets pk_M
      6. ZK proof should fail verification against pk_M
    """
    
    def test_directory_substitution_detected(self):
        """
        ZK proof generated for pk_A should fail verification against pk_M.
        This detects malicious key substitution by the directory server.
        """
        pk_A, sk_A = KeyGen()
        pk_M, sk_M = KeyGen()  # Mallory's key in the directory
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        
        # Alice generates proof with her real pk_A
        ctx_real = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        proof = prove(bytes(sk_A), bytes(pk_A), ctx_real)
        
        # Bob uses pk_M (from compromised directory) to verify
        # The context would be different because Bob computes ctx with pk_M
        ctx_bob = concat(bytes(pk_M), bytes(pk_B), bytes(ek_A))
        
        assert not verify(bytes(pk_M), ctx_bob, proof), (
            "Malicious directory: proof verified with substituted key"
        )
    
    def test_proof_with_msg0_detects_substitution(self):
        """
        Full protocol-level test: if pk_A in MSG0' doesn't match the
        directory key, the verification context is different and fails.
        """
        pk_A, sk_A = KeyGen()
        bundle_B = generate_prekey_bundle(num_opk=5)
        
        msg0, _ = sender_handshake(sk_A, pk_A, bundle_B)
        
        # Mallory substitutes pk_A in the message
        pk_M, _ = KeyGen()
        msg0.pk_A = pk_M  # Replace Alice's pk in the message
        
        # Bob processes with the modified message
        # The context will use pk_M instead of pk_A
        # The ZK proof was generated for pk_A → should fail
        with pytest.raises(AuthenticationError):
            receiver_handshake(bundle_B, msg0)


class TestProofStrippingAttack:
    """
    Attack: Mallory strips the ZK proof from MSG0'.
    
    Without the proof, the protocol should not proceed.
    """
    
    def test_null_proof_rejected(self):
        """MSG0' with a null/invalid ZK proof should be rejected."""
        pk_A, sk_A = KeyGen()
        bundle_B = generate_prekey_bundle(num_opk=5)
        
        msg0, _ = sender_handshake(sk_A, pk_A, bundle_B)
        
        # Strip the proof — replace with random bytes
        msg0.zk_proof = ZKProof(
            commitment=random_bytes(32),
            response=random_bytes(32),
            anchor=random_bytes(32)
        )
        
        with pytest.raises(AuthenticationError):
            receiver_handshake(bundle_B, msg0)
    
    def test_zero_proof_rejected(self):
        """MSG0' with all-zero proof should be rejected."""
        pk_A, sk_A = KeyGen()
        bundle_B = generate_prekey_bundle(num_opk=5)
        
        msg0, _ = sender_handshake(sk_A, pk_A, bundle_B)
        
        msg0.zk_proof = ZKProof(
            commitment=bytes(32),
            response=bytes(32),
            anchor=bytes(32)
        )
        
        with pytest.raises(AuthenticationError):
            receiver_handshake(bundle_B, msg0)


class TestReplayAttack:
    """
    Attack: Mallory replays a valid MSG0' from a previous session.
    
    The ZK proof is bound to the ephemeral key ek_A, which is fresh
    per session. Replaying the same MSG0' to a new Bob with different
    prekeys should fail because the context is different.
    """
    
    def test_replay_to_different_bob_fails(self):
        """
        Replaying MSG0' intended for Bob1 to Bob2 should produce
        a different context and the ZK proof should be invalid.
        """
        pk_A, sk_A = KeyGen()
        
        # Original session with Bob1
        bundle_B1 = generate_prekey_bundle(num_opk=5)
        msg0, ss1 = sender_handshake(sk_A, pk_A, bundle_B1)
        
        # Mallory tries to replay to Bob2
        bundle_B2 = generate_prekey_bundle(num_opk=5)
        
        # The ZK proof was bound to ctx = pk_A ‖ pk_B1 ‖ ek_A
        # Bob2 will compute ctx = pk_A ‖ pk_B2 ‖ ek_A
        # → ZK verification fails because context mismatch
        
        with pytest.raises(AuthenticationError):
            receiver_handshake(bundle_B2, msg0)
