"""
Hash-Based Commitment Scheme.

Provides a binding and hiding commitment scheme built from SHA3-256.
Used as the foundation for the Σ-protocol in Eirn-ZK.

Properties:
  - Hiding: Given C = Commit(m, r), m is computationally hidden
    (by preimage resistance of SHA3-256)
  - Binding: Cannot find (m', r') ≠ (m, r) with Commit(m', r') = C
    (by collision resistance of SHA3-256)
  - Post-Quantum: SHA3-256 with 256-bit preimage security provides
    128-bit post-quantum security (Grover's algorithm halves search)
"""

from eirn_kem.utils import sha3_256, random_bytes, concat


# Domain separation
COMMIT_LABEL = b"eirn-zk-commit-v1"


def commit(message: bytes, nonce: bytes = None) -> tuple:
    """
    Create a commitment to a message.
    
    C = SHA3-256("eirn-zk-commit-v1" ‖ message ‖ nonce)
    
    Args:
        message: The value to commit to (e.g., secret key)
        nonce: Random nonce (generated if not provided)
    
    Returns:
        (commitment, nonce) — the commitment value and opening nonce
    """
    if nonce is None:
        nonce = random_bytes(32)
    
    commitment = sha3_256(concat(COMMIT_LABEL, message, nonce))
    
    return commitment, nonce


def verify_commitment(commitment: bytes, message: bytes, nonce: bytes) -> bool:
    """
    Verify a commitment opening.
    
    Recomputes C' = SHA3-256("eirn-zk-commit-v1" ‖ message ‖ nonce)
    and checks C' == commitment.
    
    Args:
        commitment: The commitment to verify
        message: The claimed committed message
        nonce: The opening nonce
    
    Returns:
        True if the commitment is valid
    """
    expected = sha3_256(concat(COMMIT_LABEL, message, nonce))
    
    # Constant-time comparison
    return _constant_time_eq(commitment, expected)


def commit_with_context(message: bytes, context: bytes, nonce: bytes = None) -> tuple:
    """
    Create a context-bound commitment.
    
    C = SHA3-256("eirn-zk-commit-v1" ‖ message ‖ context ‖ nonce)
    
    The context binding prevents the commitment from being reused
    in a different session (replay protection).
    """
    if nonce is None:
        nonce = random_bytes(32)
    
    commitment = sha3_256(concat(COMMIT_LABEL, message, context, nonce))
    
    return commitment, nonce


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time byte comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
