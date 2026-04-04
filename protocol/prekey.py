"""
Prekey Bundle Generation.

Bob generates and uploads a prekey bundle to the server, containing:
  - pk_B:     Identity public key
  - spk_B:    Signed prekey (committed via KEM, not signed traditionally)
  - opk_B[]:  One-time prekeys (consumed per session)
  - com_B:    KEM commitment (H(ssk_B ‖ spk_B ‖ "prekey-commit"))

The commitment com_B replaces digital signatures: Bob proves ownership
of the prekey during the first session by revealing a value that hashes
to com_B. This is a novel contribution of Eirn-AKE.
"""

from dataclasses import dataclass, field
from typing import List, Tuple

from eirn_kem.kem import (
    KeyGen, EirnPublicKey, EirnSecretKey
)
from eirn_kem.utils import sha3_256, random_bytes, concat
from eirn_kem.params import EirnParams, DEFAULT_PARAMS


# Domain separation
PREKEY_COMMIT_LABEL = b"eirn-prekey-commit-v1"


@dataclass
class PrekeyBundle:
    """
    Bob's prekey bundle uploaded to the server.
    
    In a real deployment, this would be stored on an untrusted
    key distribution server. The ZK extension in Eirn-ZK protects
    against a malicious server that might substitute keys.
    """
    # Identity key
    pk_B: EirnPublicKey         # Bob's long-term identity public key
    sk_B: EirnSecretKey         # Bob's long-term identity secret key (kept local)
    
    # Signed prekey
    spk_B: EirnPublicKey        # Bob's signed prekey (public)
    ssk_B: EirnSecretKey        # Bob's signed prekey (secret, kept local)
    
    # One-time prekeys
    opk_list: List[Tuple[EirnPublicKey, EirnSecretKey]]  # (public, secret) pairs
    
    # KEM commitment (replaces signature on prekey)
    com_B: bytes                # H(ssk_B ‖ spk_B ‖ "prekey-commit")
    
    def get_public_bundle(self) -> dict:
        """
        Return only the public components (what gets uploaded to the server).
        Secret keys are NEVER sent.
        """
        return {
            "pk_B": self.pk_B,
            "spk_B": self.spk_B,
            "opk_list": [opk for opk, _ in self.opk_list],
            "com_B": self.com_B,
        }
    
    def consume_opk(self) -> Tuple[EirnPublicKey, EirnSecretKey]:
        """
        Consume and remove a one-time prekey.
        Each OPK is used for exactly one session (forward secrecy).
        """
        if not self.opk_list:
            raise ValueError("No one-time prekeys remaining")
        return self.opk_list.pop(0)


def generate_prekey_bundle(
    num_opk: int = 10,
    params: EirnParams = None,
    sk_B: EirnSecretKey = None,
    pk_B: EirnPublicKey = None,
) -> PrekeyBundle:
    """
    Generate a complete prekey bundle for Bob.
    
    Args:
        num_opk: Number of one-time prekeys to generate
        params: Eirn-KEM parameter set
        sk_B: Existing identity secret key (generates new if None)
        pk_B: Existing identity public key (generates new if None)
    
    Returns:
        PrekeyBundle with all keys and commitment
    """
    params = params or DEFAULT_PARAMS
    
    # Identity keypair (or reuse existing)
    if sk_B is None or pk_B is None:
        pk_B, sk_B = KeyGen(params)
    
    # Signed prekey
    spk_B, ssk_B = KeyGen(params)
    
    # One-time prekeys
    opk_list = [KeyGen(params) for _ in range(num_opk)]
    
    # KEM commitment: H(ssk_B ‖ spk_B ‖ "prekey-commit")
    com_B = sha3_256(concat(
        bytes(ssk_B),
        bytes(spk_B),
        PREKEY_COMMIT_LABEL
    ))
    
    return PrekeyBundle(
        pk_B=pk_B,
        sk_B=sk_B,
        spk_B=spk_B,
        ssk_B=ssk_B,
        opk_list=opk_list,
        com_B=com_B,
    )
