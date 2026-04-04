"""
NAXOS-KEM: Authenticated Key Encapsulation with eCK Security.

Implements the NAXOS trick adapted to the KEM setting,
providing implicit authentication via the sender's long-term key.
"""

from .naxos import naxos_encaps, naxos_decaps

__all__ = ["naxos_encaps", "naxos_decaps"]
