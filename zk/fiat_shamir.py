"""
Fiat-Shamir Transform.

Converts the interactive Σ-protocol into a non-interactive proof
by deriving the verifier's challenge from the transcript hash.

Security: In the Random Oracle Model (ROM), the Fiat-Shamir transform
preserves soundness. In the Quantum ROM (QROM), additional care is
needed — see [Don et al., 2019] for the QROM Fiat-Shamir analysis.
For this research prototype, we assume the classical ROM analysis suffices.
"""

from eirn_kem.utils import sha3_256, concat


# Domain separation
FS_LABEL = b"eirn-zk-fs-v1"


def derive_challenge(
    commitment: bytes,
    public_key: bytes,
    context: bytes,
    auxiliary: bytes = b""
) -> bytes:
    """
    Derive a Fiat-Shamir challenge from the transcript.
    
    c = SHA3-256("eirn-zk-fs-v1" ‖ commitment ‖ pk ‖ ctx ‖ auxiliary)
    
    The challenge is derived deterministically from:
    - The prover's commitment (first message)
    - The public key (statement being proved)
    - The session context (freshness / replay protection)
    - Optional auxiliary data
    
    This replaces the interactive verifier's random challenge.
    
    Args:
        commitment: Prover's commitment value (Σ-protocol first message)
        public_key: Public key bytes (the statement)
        context: Session context (pk_A ‖ pk_B ‖ ek_A)
        auxiliary: Additional data to bind into the challenge
    
    Returns:
        32-byte challenge value
    """
    return sha3_256(concat(
        FS_LABEL,
        commitment,
        public_key,
        context,
        auxiliary
    ))


def derive_challenge_from_transcript(
    transcript_parts: list,
    label: bytes = FS_LABEL
) -> bytes:
    """
    Derive a challenge from a full transcript.
    
    More general version that hashes an arbitrary list of transcript parts.
    Each part is length-prefixed to prevent ambiguity.
    """
    import struct
    
    buf = bytearray(label)
    for part in transcript_parts:
        buf.extend(struct.pack(">I", len(part)))
        buf.extend(part)
    
    return sha3_256(bytes(buf))
