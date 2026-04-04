"""
Tests for ZK Proof System: Σ-Protocol with Fiat-Shamir.

Verifies:
  - Completeness: valid proof accepted
  - Soundness: invalid proof rejected (wrong sk, tampered proof)
  - Zero-Knowledge: proof reveals no information about sk
  - Replay protection: proof bound to context
  - Serialization: proof round-trips through bytes
"""

import pytest
from eirn_kem.kem import KeyGen
from eirn_kem.utils import random_bytes, concat, sha3_256
from zk.sigma import prove, verify, ZKProof, _verify_with_secret


class TestCompleteness:
    """Test that honest provers always produce accepting proofs."""
    
    def test_valid_proof_accepted(self):
        """An honest proof with correct sk_A should be accepted."""
        pk_A, sk_A = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        proof = prove(
            sk_A=bytes(sk_A),
            pk_A=bytes(pk_A),
            ctx=ctx
        )
        
        assert verify(bytes(pk_A), ctx, proof), (
            "Completeness violation: honest proof was rejected"
        )
    
    def test_valid_proof_with_secret_verification(self):
        """Full verification (with sk) should also accept."""
        pk_A, sk_A = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        proof = prove(bytes(sk_A), bytes(pk_A), ctx)
        
        assert _verify_with_secret(bytes(sk_A), bytes(pk_A), ctx, proof)
    
    def test_100_valid_proofs(self):
        """100 independent proofs should all be accepted (statistical check)."""
        pk_A, sk_A = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        for i in range(100):
            proof = prove(bytes(sk_A), bytes(pk_A), ctx)
            assert verify(bytes(pk_A), ctx, proof), f"Proof {i} rejected"


class TestSoundness:
    """Test that invalid proofs are rejected."""
    
    def test_wrong_sk_rejected(self):
        """A proof made with wrong sk should be rejected by _verify_with_secret."""
        pk_A, sk_A = KeyGen()
        _, sk_wrong = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        # Generate proof with WRONG secret key
        proof = prove(bytes(sk_wrong), bytes(pk_A), ctx)
        
        # The anchor v will be wrong since sk_wrong != sk_A
        assert not _verify_with_secret(bytes(sk_A), bytes(pk_A), ctx, proof), (
            "Soundness violation: proof with wrong sk was accepted by full verifier"
        )
    
    def test_tampered_commitment_rejected(self):
        """Modifying the commitment should invalidate the proof."""
        pk_A, sk_A = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        proof = prove(bytes(sk_A), bytes(pk_A), ctx)
        
        # Tamper with commitment
        tampered = ZKProof(
            commitment=random_bytes(32),
            response=proof.response,
            anchor=proof.anchor
        )
        
        assert not verify(bytes(pk_A), ctx, tampered), (
            "Tampered commitment should be rejected"
        )
    
    def test_tampered_response_rejected(self):
        """Modifying the response should invalidate the proof."""
        pk_A, sk_A = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        proof = prove(bytes(sk_A), bytes(pk_A), ctx)
        
        tampered = ZKProof(
            commitment=proof.commitment,
            response=random_bytes(32),
            anchor=proof.anchor
        )
        
        assert not verify(bytes(pk_A), ctx, tampered), (
            "Tampered response should be rejected"
        )
    
    def test_tampered_anchor_rejected(self):
        """Modifying the anchor should invalidate the proof."""
        pk_A, sk_A = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        proof = prove(bytes(sk_A), bytes(pk_A), ctx)
        
        tampered = ZKProof(
            commitment=proof.commitment,
            response=proof.response,
            anchor=random_bytes(32)
        )
        
        assert not verify(bytes(pk_A), ctx, tampered), (
            "Tampered anchor should be rejected"
        )
    
    def test_zero_proof_rejected(self):
        """All-zero proof should be rejected."""
        pk_A, sk_A = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        zero_proof = ZKProof(
            commitment=bytes(32),
            response=bytes(32),
            anchor=bytes(32)
        )
        
        assert not verify(bytes(pk_A), ctx, zero_proof)
    
    def test_swapped_components_rejected(self):
        """Swapping proof components should be rejected."""
        pk_A, sk_A = KeyGen()
        pk_B, _ = KeyGen()
        ek_A, _ = KeyGen()
        ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))
        
        proof = prove(bytes(sk_A), bytes(pk_A), ctx)
        
        # Swap commitment and response
        swapped = ZKProof(
            commitment=proof.response,
            response=proof.commitment,
            anchor=proof.anchor
        )
        
        assert not verify(bytes(pk_A), ctx, swapped)


class TestReplayProtection:
    """Test that proofs are bound to their context."""
    
    def test_different_context_rejected(self):
        """A proof should not verify under a different context."""
        pk_A, sk_A = KeyGen()
        pk_B, _ = KeyGen()
        ek_A1, _ = KeyGen()
        ek_A2, _ = KeyGen()
        
        ctx1 = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A1))
        ctx2 = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A2))
        
        # Proof for context 1
        proof = prove(bytes(sk_A), bytes(pk_A), ctx1)
        
        # Should verify under ctx1
        assert verify(bytes(pk_A), ctx1, proof)
        
        # Should NOT verify under ctx2 (different ephemeral key)
        assert not verify(bytes(pk_A), ctx2, proof), (
            "Replay protection failed: proof accepted under different context"
        )
    
    def test_different_pk_B_rejected(self):
        """A proof should not verify if Bob's key changes."""
        pk_A, sk_A = KeyGen()
        pk_B1, _ = KeyGen()
        pk_B2, _ = KeyGen()
        ek_A, _ = KeyGen()
        
        ctx1 = concat(bytes(pk_A), bytes(pk_B1), bytes(ek_A))
        ctx2 = concat(bytes(pk_A), bytes(pk_B2), bytes(ek_A))
        
        proof = prove(bytes(sk_A), bytes(pk_A), ctx1)
        
        assert verify(bytes(pk_A), ctx1, proof)
        assert not verify(bytes(pk_A), ctx2, proof)


class TestSerialization:
    """Test proof serialization."""
    
    def test_roundtrip_serialization(self):
        """Proof should survive serialization/deserialization."""
        pk_A, sk_A = KeyGen()
        ctx = random_bytes(64)
        
        proof = prove(bytes(sk_A), bytes(pk_A), ctx)
        
        # Serialize and deserialize
        proof_bytes = proof.to_bytes()
        proof_restored = ZKProof.from_bytes(proof_bytes)
        
        assert proof.commitment == proof_restored.commitment
        assert proof.response == proof_restored.response
        assert proof.anchor == proof_restored.anchor
    
    def test_proof_size(self):
        """Proof should be exactly 96 bytes."""
        pk_A, sk_A = KeyGen()
        ctx = random_bytes(64)
        
        proof = prove(bytes(sk_A), bytes(pk_A), ctx)
        
        assert len(proof.to_bytes()) == 96, (
            f"Expected 96 bytes, got {len(proof.to_bytes())}"
        )
    
    def test_invalid_size_rejected(self):
        """Deserialization should reject wrong-sized input."""
        with pytest.raises(ValueError):
            ZKProof.from_bytes(random_bytes(64))
        
        with pytest.raises(ValueError):
            ZKProof.from_bytes(random_bytes(128))


class TestZeroKnowledge:
    """Test zero-knowledge property (informal)."""
    
    def test_different_witnesses_same_validity(self):
        """Different witnesses (random nonces) should all produce valid proofs."""
        pk_A, sk_A = KeyGen()
        ctx = random_bytes(64)
        
        for _ in range(50):
            proof = prove(bytes(sk_A), bytes(pk_A), ctx)
            assert verify(bytes(pk_A), ctx, proof)
    
    def test_proofs_are_unique(self):
        """Each proof should be unique (different random witness)."""
        pk_A, sk_A = KeyGen()
        ctx = random_bytes(64)
        
        proofs = [prove(bytes(sk_A), bytes(pk_A), ctx).to_bytes() for _ in range(10)]
        
        # All proofs should be distinct
        assert len(set(proofs)) == 10, (
            "ZK proofs should be unique due to random witness"
        )
    
    def test_proof_does_not_reveal_sk(self):
        """
        Proof components should not contain sk directly.
        (This is a basic check — real ZK requires simulation argument.)
        """
        pk_A, sk_A = KeyGen()
        ctx = random_bytes(64)
        sk_bytes = bytes(sk_A)
        
        proof = prove(sk_bytes, bytes(pk_A), ctx)
        proof_bytes = proof.to_bytes()
        
        # sk should not appear in the proof
        assert sk_bytes not in proof_bytes, (
            "Secret key appears directly in proof — ZK violation"
        )
