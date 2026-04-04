"""
Session Key Derivation.

Derives the final session key from the four KEM shared secrets
and the full protocol transcript. Uses SHAKE256 as the KDF with
domain separation and length-prefixed encoding.

The session key binds to:
  - All four shared secrets (K1, K2, K3, K4)
  - Both parties' identity public keys
  - Alice's ephemeral public key
  - All four ciphertexts (transcript binding)
  - Protocol version label
"""

from typing import List
from eirn_kem.utils import kdf, concat


# Protocol version label
SESSION_LABEL = "Eirn-ZK-v1"


def derive_session_key(
    shared_secrets: List[bytes],
    pk_A: bytes,
    pk_B: bytes,
    ek_A: bytes,
    ciphertexts: List[bytes],
    additional_data: bytes = b""
) -> bytes:
    """
    Derive the session key from KEM outputs and transcript.
    
    ss = KDF(K1 ‖ K2 ‖ K3 ‖ K4 ‖ pk_A ‖ pk_B ‖ ek_A 
             ‖ ct1 ‖ ct2 ‖ ct3 ‖ ct4 ‖ additional_data,
             label="Eirn-ZK-v1")
    
    The full transcript binding ensures that any modification to
    the handshake messages (even by a MITM) results in a different
    session key, causing the protocol to fail.
    
    Args:
        shared_secrets: [K1, K2, K3, K4] from KEM decapsulations
        pk_A: Alice's identity public key bytes
        pk_B: Bob's identity public key bytes
        ek_A: Alice's ephemeral public key bytes
        ciphertexts: [ct1, ct2, ct3, ct4] ciphertext bytes
        additional_data: Optional additional binding data
    
    Returns:
        32-byte session key
    """
    inputs = (
        shared_secrets + 
        [pk_A, pk_B, ek_A] + 
        ciphertexts +
        ([additional_data] if additional_data else [])
    )
    
    return kdf(inputs, SESSION_LABEL, output_len=32)


def derive_message_key(session_key: bytes, counter: int) -> bytes:
    """
    Derive a per-message encryption key from the session key.
    
    msg_key = KDF(session_key ‖ counter, label="Eirn-ZK-msg")
    
    This provides forward secrecy at the message level within a session.
    """
    counter_bytes = counter.to_bytes(8, "big")
    return kdf([session_key, counter_bytes], "Eirn-ZK-msg", output_len=32)
