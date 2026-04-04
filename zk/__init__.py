"""
ZK: Zero-Knowledge Proof System for Eirn-ZK.

Provides a hash-commitment-based Σ-protocol with Fiat-Shamir
transformation for non-interactive proof of knowledge of a
KEM secret key.
"""

from .sigma import prove, verify, ZKProof

__all__ = ["prove", "verify", "ZKProof"]
