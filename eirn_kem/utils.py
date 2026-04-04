"""
Cryptographic Utility Functions.

Provides hash functions, KDF, XOF, and serialization helpers
used throughout Eirn-ZK. All functions use Python's hashlib
(SHA-3 family) for consistency with the post-quantum setting.
"""

import hashlib
import os
import struct
from typing import List


# ─── Hash Functions ───────────────────────────────────────────────

def sha3_256(data: bytes) -> bytes:
    """SHA3-256: 32-byte output."""
    return hashlib.sha3_256(data).digest()


def sha3_512(data: bytes) -> bytes:
    """SHA3-512: 64-byte output."""
    return hashlib.sha3_512(data).digest()


def shake128(data: bytes, length: int) -> bytes:
    """SHAKE128: variable-length XOF output."""
    return hashlib.shake_128(data).digest(length)


def shake256(data: bytes, length: int) -> bytes:
    """SHAKE256: variable-length XOF output."""
    return hashlib.shake_256(data).digest(length)


# ─── Key Derivation Function ─────────────────────────────────────

def kdf(inputs: List[bytes], label: str, output_len: int = 32) -> bytes:
    """
    Domain-separated Key Derivation Function.
    
    KDF(inputs, label) = SHAKE256(label_bytes ‖ len(inputs) ‖ 
                                   len(x1) ‖ x1 ‖ len(x2) ‖ x2 ‖ ...,
                                   output_len)
    
    The length-prefix encoding prevents ambiguity in concatenation.
    
    Args:
        inputs: List of byte strings to derive from
        label: Domain separation label (e.g., "Eirn-ZK-v1")
        output_len: Desired output length in bytes
    
    Returns:
        Derived key material of output_len bytes
    """
    label_bytes = label.encode("utf-8")
    
    # Build the KDF input with unambiguous encoding
    buf = bytearray()
    buf.extend(struct.pack(">H", len(label_bytes)))  # label length (2 bytes)
    buf.extend(label_bytes)
    buf.extend(struct.pack(">H", len(inputs)))        # number of inputs
    
    for inp in inputs:
        buf.extend(struct.pack(">I", len(inp)))       # input length (4 bytes)
        buf.extend(inp)
    
    return shake256(bytes(buf), output_len)


# ─── Random Bytes ─────────────────────────────────────────────────

def random_bytes(n: int) -> bytes:
    """Generate n cryptographically secure random bytes."""
    return os.urandom(n)


# ─── Deterministic Sampling ──────────────────────────────────────

def xof_sample(seed: bytes, label: bytes, length: int) -> bytes:
    """
    Deterministic sampling from an XOF.
    
    Used where we need reproducible randomness from a seed,
    e.g., for KEM encapsulation coins.
    """
    return shake256(label + seed, length)


# ─── Serialization Helpers ───────────────────────────────────────

def concat(*parts: bytes) -> bytes:
    """Concatenate multiple byte strings."""
    return b"".join(parts)


def encode_length_prefixed(data: bytes) -> bytes:
    """Encode data with a 4-byte big-endian length prefix."""
    return struct.pack(">I", len(data)) + data


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string for display."""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string back to bytes."""
    return bytes.fromhex(hex_str)
