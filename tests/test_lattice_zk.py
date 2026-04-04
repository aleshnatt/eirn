"""
Test Suite for Lattice-Native ZKPoK.
"""

import os
import pytest
from lattice_zk.params import ZKPARAMS_512
from lattice_zk.keygen import derive_lattice_keys
from lattice_zk.prove import lattice_prove
from lattice_zk.verify import lattice_verify
from eirn_kem.utils import random_bytes

def test_lattice_zkpok_flow():
    """Test the complete Derive -> Prove -> Verify lifecycle."""
    kem_seed = random_bytes(32)
    ctx = b"test-context-123"

    # Derive keys
    pk_zk, sk_zk = derive_lattice_keys(kem_seed, params=ZKPARAMS_512)

    # Prove
    proof = lattice_prove(sk_zk, ctx, params=ZKPARAMS_512)
    assert proof is not None, "Prover failed to generate proof"

    # Verify
    valid = lattice_verify(pk_zk, ctx, proof, params=ZKPARAMS_512)
    assert valid is True, "Verification failed for honest proof"

def test_lattice_zkpok_wrong_context():
    """Test that proof verification fails if context is tampered."""
    kem_seed = random_bytes(32)
    ctx1 = b"honest-context"
    ctx2 = b"tampered-context"

    pk_zk, sk_zk = derive_lattice_keys(kem_seed, params=ZKPARAMS_512)
    proof = lattice_prove(sk_zk, ctx1, params=ZKPARAMS_512)

    valid = lattice_verify(pk_zk, ctx2, proof, params=ZKPARAMS_512)
    assert valid is False, "Verification should fail with wrong context"

def test_lattice_zkpok_wrong_key():
    """Test that proof verification fails if verified against wrong pk."""
    kem_seed1 = random_bytes(32)
    kem_seed2 = random_bytes(32)
    ctx = b"test-context"

    pk_zk1, sk_zk1 = derive_lattice_keys(kem_seed1, params=ZKPARAMS_512)
    pk_zk2, sk_zk2 = derive_lattice_keys(kem_seed2, params=ZKPARAMS_512)

    proof = lattice_prove(sk_zk1, ctx, params=ZKPARAMS_512)

    # Verify proof from sk1 against pk2
    valid = lattice_verify(pk_zk2, ctx, proof, params=ZKPARAMS_512)
    assert valid is False, "Verification should fail with wrong public key"
