"""
Tests for Eirn-KEM: Key Encapsulation Mechanism.

Verifies:
  - KeyGen produces valid keypairs
  - Encaps/Decaps round-trip produces matching shared secrets
  - Wrong key rejection (implicit reject via FO transform)
  - Deterministic encapsulation with explicit coins
"""

import pytest
from eirn_kem.kem import KeyGen, Encaps, Decaps, EncapsDeterministic
from eirn_kem.params import PARAMS_512, PARAMS_768
from eirn_kem.utils import random_bytes


class TestKeyGen:
    """Test KEM key generation."""
    
    def test_keygen_produces_keys(self):
        """KeyGen should produce non-empty pk and sk."""
        pk, sk = KeyGen()
        assert len(bytes(pk)) == 32  # SHA3-256 output
        assert len(sk.seed) == 32
    
    def test_keygen_produces_unique_keys(self):
        """Each KeyGen call should produce different keys."""
        pk1, sk1 = KeyGen()
        pk2, sk2 = KeyGen()
        assert bytes(pk1) != bytes(pk2)
        assert sk1.seed != sk2.seed
    
    def test_keygen_pk_derived_from_sk(self):
        """pk should be deterministically derived from sk."""
        pk, sk = KeyGen()
        assert pk.data == sk.pk_data


class TestEncapsDecaps:
    """Test KEM encapsulation and decapsulation."""
    
    def test_roundtrip_512(self):
        """Encaps → Decaps should produce the same shared secret (Eirn-512)."""
        pk, sk = KeyGen(PARAMS_512)
        ct, ss_encaps = Encaps(pk)
        ss_decaps = Decaps(sk, ct)
        assert ss_encaps == ss_decaps, (
            "Shared secret mismatch: Encaps and Decaps produced different values"
        )
    
    def test_roundtrip_768(self):
        """Encaps → Decaps should produce the same shared secret (Eirn-768)."""
        pk, sk = KeyGen(PARAMS_768)
        ct, ss_encaps = Encaps(pk)
        ss_decaps = Decaps(sk, ct)
        assert ss_encaps == ss_decaps
    
    def test_shared_secret_length(self):
        """Shared secret should be 32 bytes (256 bits)."""
        pk, sk = KeyGen()
        ct, ss = Encaps(pk)
        assert len(ss) == 32
    
    def test_ciphertext_is_bytes(self):
        """Ciphertext should be serializable to bytes."""
        pk, sk = KeyGen()
        ct, ss = Encaps(pk)
        ct_bytes = bytes(ct)
        assert len(ct_bytes) > 0
    
    def test_different_encaps_different_secrets(self):
        """Two encapsulations to the same pk should produce different secrets."""
        pk, sk = KeyGen()
        ct1, ss1 = Encaps(pk)
        ct2, ss2 = Encaps(pk)
        assert ss1 != ss2, "Two encapsulations should not produce the same secret"
    
    def test_wrong_key_rejection(self):
        """Decaps with wrong sk should produce a different shared secret."""
        pk1, sk1 = KeyGen()
        pk2, sk2 = KeyGen()
        ct, ss_correct = Encaps(pk1)
        ss_wrong = Decaps(sk2, ct)
        assert ss_correct != ss_wrong, (
            "Wrong key should produce different shared secret (implicit reject)"
        )
    
    def test_deterministic_encaps(self):
        """Encaps with same coins should produce same (ct, ss)."""
        pk, sk = KeyGen()
        coins = random_bytes(32)
        ct1, ss1 = EncapsDeterministic(pk, coins)
        ct2, ss2 = EncapsDeterministic(pk, coins)
        assert bytes(ct1) == bytes(ct2)
        assert ss1 == ss2
    
    def test_deterministic_encaps_different_coins(self):
        """Different coins should produce different (ct, ss)."""
        pk, sk = KeyGen()
        coins1 = random_bytes(32)
        coins2 = random_bytes(32)
        ct1, ss1 = EncapsDeterministic(pk, coins1)
        ct2, ss2 = EncapsDeterministic(pk, coins2)
        assert bytes(ct1) != bytes(ct2)
        assert ss1 != ss2


class TestMultipleRoundtrips:
    """Stress test with multiple round-trips."""
    
    def test_100_roundtrips(self):
        """100 consecutive round-trips should all succeed."""
        pk, sk = KeyGen()
        for i in range(100):
            ct, ss_enc = Encaps(pk)
            ss_dec = Decaps(sk, ct)
            assert ss_enc == ss_dec, f"Round-trip {i} failed"
