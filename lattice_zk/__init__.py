"""
Lattice-Native ZKPoK Module.

Provides a formal Zero-Knowledge Proof of Knowledge for the MLWE
key derivation relation used in Eirn-KEM, replacing the hash-based
Key Consistency Proof with a Lyubashevsky rejection-sampling
Σ-protocol that achieves extract extractability.

Usage:
    from lattice_zk import (
        derive_lattice_keys, lattice_prove, lattice_verify,
        ZKPARAMS_512, KcpMode
    )

    # Derive lattice keys from KEM seed
    pk_zk, sk_zk = derive_lattice_keys(kem_seed)

    # Generate proof
    proof = lattice_prove(sk_zk, ctx)

    # Verify proof
    valid = lattice_verify(pk_zk, ctx, proof)

Cipher Suite Modes:
    KcpMode.LITE   — Original 96-byte hash-based KCP (v1.1)
    KcpMode.STRICT — Lattice-native ZKPoK (~1.3 KB, full extractability)
"""

from enum import Enum

from .params import LatticeZKParams, ZKPARAMS_512, ZKPARAMS_768, DEFAULT_ZK_PARAMS
from .keygen import derive_lattice_keys, LatticePublicKey, LatticeSecretKey
from .prove import lattice_prove, LatticeZKProof
from .verify import lattice_verify


class KcpMode(Enum):
    """
    KCP Protocol Mode Selection.

    LITE:   96-byte hash-based KCP (wrong-key soundness only).
            Minimal bandwidth, no extractability.
            Suitable for bandwidth-constrained environments.

    STRICT: ~1.3 KB Lattice-native ZKPoK (full PoK extractability).
            Formal knowledge extraction via Lyubashevsky Σ-protocol.
            Required for applications needing active-forger resistance.
    """
    LITE = "kcp-lite"
    STRICT = "kcp-strict"


__all__ = [
    "KcpMode",
    "LatticeZKParams",
    "ZKPARAMS_512",
    "ZKPARAMS_768",
    "DEFAULT_ZK_PARAMS",
    "derive_lattice_keys",
    "LatticePublicKey",
    "LatticeSecretKey",
    "lattice_prove",
    "lattice_verify",
    "LatticeZKProof",
]
