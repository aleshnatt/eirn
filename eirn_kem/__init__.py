"""
Eirn-KEM: Simulated Module-LWE Key Encapsulation Mechanism.

This module provides a hash-based simulation of the Eirn-KEM primitive
for protocol-level testing. The KEM interface (KeyGen, Encaps, Decaps)
is functionally correct but uses hash constructions instead of real
MLWE arithmetic.

In production, this would be replaced with the actual C implementation
of Eirn-KEM with NTT-based polynomial arithmetic over Z_q[X]/(X^256+1).
"""

from .kem import KeyGen, Encaps, Decaps
from .params import PARAMS_512, PARAMS_768

__all__ = ["KeyGen", "Encaps", "Decaps", "PARAMS_512", "PARAMS_768"]
