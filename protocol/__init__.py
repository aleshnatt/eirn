"""
Protocol: Eirn-ZK Authenticated Key Exchange.

Implements the full Eirn-ZK protocol flow including prekey bundles,
MSG0' handshake with ZK proof, and session key derivation.
"""

from .handshake import sender_handshake, receiver_handshake, MSG0Prime
from .prekey import PrekeyBundle, generate_prekey_bundle
from .session import derive_session_key

__all__ = [
    "sender_handshake", "receiver_handshake", "MSG0Prime",
    "PrekeyBundle", "generate_prekey_bundle",
    "derive_session_key",
]
