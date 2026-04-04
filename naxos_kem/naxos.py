"""
NAXOS-KEM: NAXOS Trick Adapted to Module-LWE KEM.

The NAXOS trick (LaMacchia, Lauter, Mityagin 2007) provides eCK security
by deriving encapsulation randomness from BOTH the sender's long-term
secret key AND ephemeral secret key:

    r_nax = H(sk_S ‖ H(esk_S) ‖ pk_R ‖ "eirn-naxos-v1")

This ensures that an adversary must compromise BOTH sk_S and esk_S
to recompute the randomness — providing resilience against:
  - Ephemeral key compromise (knows esk_S but not sk_S)
  - Long-term key compromise (knows sk_S but not esk_S)

This is the core authentication primitive in Eirn-AKE.
"""

from typing import Tuple

from eirn_kem.kem import (
    EirnPublicKey, EirnSecretKey, EirnCiphertext,
    Encaps, Decaps, EncapsDeterministic
)
from eirn_kem.utils import sha3_256, sha3_512, concat


# Domain separation labels
NAXOS_LABEL = b"eirn-naxos-v1"
NAXOS_COINS_LABEL = b"eirn-naxos-coins"


def naxos_derive_coins(
    sk_S: EirnSecretKey,
    esk_S: EirnSecretKey,
    pk_R: EirnPublicKey,
    context: bytes = b""
) -> bytes:
    """
    Derive NAXOS randomness from sender's keys.
    
    r_nax = H(sk_S ‖ H(esk_S) ‖ pk_R ‖ context ‖ "eirn-naxos-v1")
    
    This is the "NAXOS trick": the coins depend on BOTH keys.
    
    Args:
        sk_S: Sender's long-term secret key
        esk_S: Sender's ephemeral secret key
        pk_R: Recipient's public key
        context: Additional context binding (pk_A ‖ pk_B ‖ nonce)
    
    Returns:
        32-byte deterministic coins for KEM encapsulation
    """
    # Hash ephemeral key first (prevents length-extension issues)
    h_esk = sha3_256(bytes(esk_S))
    
    # Derive NAXOS coins
    r_nax = sha3_256(concat(
        bytes(sk_S),     # long-term secret
        h_esk,           # hashed ephemeral secret
        bytes(pk_R),     # recipient's public key
        context,         # session context
        NAXOS_LABEL      # domain separation
    ))
    
    return r_nax


def naxos_encaps(
    pk_R: EirnPublicKey,
    sk_S: EirnSecretKey,
    esk_S: EirnSecretKey,
    context: bytes = b""
) -> Tuple[EirnCiphertext, bytes]:
    """
    NAXOS-KEM Encapsulation (Authenticated).
    
    Produces a ciphertext and shared secret where the encapsulation
    randomness is derived from the sender's long-term AND ephemeral keys.
    
    eCK Security Property:
        - Adversary with esk_S (no sk_S): cannot compute r_nax → cannot replay
        - Adversary with sk_S (no esk_S): cannot compute r_nax → forward secrecy
        - Must compromise BOTH to break authentication
    
    Args:
        pk_R: Recipient's public key (Bob)
        sk_S: Sender's long-term secret key (Alice)
        esk_S: Sender's ephemeral secret key (Alice)
        context: Binding context for the session
    
    Returns:
        (ciphertext, shared_secret)
    """
    # Step 1: Derive NAXOS coins
    r_nax = naxos_derive_coins(sk_S, esk_S, pk_R, context)
    
    # Step 2: Deterministic encapsulation with NAXOS coins
    ct, ss_raw = EncapsDeterministic(pk_R, r_nax)
    
    # Step 3: Bind shared secret to authentication context
    # ss = H("naxos-ss" ‖ ss_raw ‖ pk_S ‖ pk_R ‖ context)
    ss = sha3_256(concat(
        b"naxos-ss",
        ss_raw,
        sk_S.pk_data,    # sender's public key
        bytes(pk_R),     # recipient's public key
        context
    ))
    
    return ct, ss


def naxos_decaps(
    sk_R: EirnSecretKey,
    ct: EirnCiphertext,
    pk_S: EirnPublicKey = None,
    context: bytes = b""
) -> bytes:
    """
    NAXOS-KEM Decapsulation.
    
    Standard KEM decapsulation — the receiver does NOT need the sender's
    secret key. The NAXOS trick only affects the encapsulation side.
    
    The receiver uses their own secret key to decapsulate, then binds
    the shared secret to the authentication context.
    
    Args:
        sk_R: Recipient's secret key (Bob)
        ct: Ciphertext from NAXOS encapsulation
        pk_S: Sender's public key (for context binding)
        context: Session context (must match encapsulation)
    
    Returns:
        shared_secret (32 bytes)
    """
    # Step 1: Standard Eirn decapsulation
    ss_raw = Decaps(sk_R, ct)
    
    # Step 2: Bind to authentication context (must match encaps)
    if pk_S is not None:
        ss = sha3_256(concat(
            b"naxos-ss",
            ss_raw,
            bytes(pk_S),     # sender's public key
            sk_R.pk_data,    # recipient's public key
            context
        ))
    else:
        ss = ss_raw
    
    return ss
