"""
Eirn-Ratchet: KEM-based Key Ratchet with ZK Identity Binding.

Provides continuous post-quantum forward secrecy through KEM-based
ratcheting, with each ratchet key rotation bound to the long-term
identity via a lattice ZKPoK proof.

Usage:
    from ratchet import RatchetState, ratchet_step, ratchet_receive
"""

from .state import RatchetState, RatchetMessage
from .ratchet import ratchet_step, ratchet_receive

__all__ = [
    "RatchetState",
    "RatchetMessage",
    "ratchet_step",
    "ratchet_receive",
]
