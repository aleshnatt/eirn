"""
Eirn-KEM: Simulated Key Encapsulation Mechanism.

Provides a hash-based simulation of the Eirn-KEM primitive preserving
the correct IND-CCA2 KEM interface (KeyGen, Encaps, Decaps).

Simulation model:
    pk = H("pk" ‖ sk)
    Encaps encrypts coins with a stream cipher keyed by pk.
    Decaps recovers coins via sk → pk → stream key.
"""

from dataclasses import dataclass
from typing import Tuple, Optional

from .params import EirnParams, DEFAULT_PARAMS
from .utils import sha3_256, shake256, random_bytes, concat

# Prefix used for pk derivation — also referenced by the ZK module.
KEY_DERIVE_PREFIX = b"eirn-keygen-pk"


# ─── Key / Ciphertext types ─────────────────────────────────────

@dataclass
class EirnPublicKey:
    data: bytes
    params: EirnParams
    def __bytes__(self) -> bytes:
        return self.data

@dataclass
class EirnSecretKey:
    seed: bytes
    pk_data: bytes
    params: EirnParams
    def __bytes__(self) -> bytes:
        return self.seed

@dataclass
class EirnCiphertext:
    data: bytes
    params: EirnParams
    def __bytes__(self) -> bytes:
        return self.data


# ─── KEM Operations ─────────────────────────────────────────────

def KeyGen(params: EirnParams = None) -> Tuple[EirnPublicKey, EirnSecretKey]:
    """Generate an Eirn-KEM keypair.  pk = H(prefix ‖ sk)."""
    params = params or DEFAULT_PARAMS
    sk_seed = random_bytes(params.sk_bytes)
    pk_data = sha3_256(KEY_DERIVE_PREFIX + sk_seed)
    pk = EirnPublicKey(data=pk_data, params=params)
    sk = EirnSecretKey(seed=sk_seed, pk_data=pk_data, params=params)
    return pk, sk


def Encaps(
    pk: EirnPublicKey,
    params: EirnParams = None,
    coins: Optional[bytes] = None,
) -> Tuple[EirnCiphertext, bytes]:
    """
    Encapsulate: produce (ciphertext, shared_secret).

    ct = nonce ‖ (coins ⊕ mask)
       where mask = SHAKE256("eirn-fo-mask" ‖ pk ‖ nonce, 32)
       and   nonce = H("eirn-nonce" ‖ pk ‖ coins)

    ss = H("eirn-ss" ‖ pk ‖ coins)
    """
    params = params or pk.params
    if coins is None:
        coins = random_bytes(params.coins_bytes)

    pk_b = bytes(pk)

    # Deterministic nonce derived from pk and coins
    nonce = sha3_256(b"eirn-nonce" + pk_b + coins)

    # Stream-cipher mask derived from pk and nonce (public-key encryption sim)
    mask = shake256(b"eirn-fo-mask" + pk_b + nonce, len(coins))

    encrypted_coins = bytes(a ^ b for a, b in zip(coins, mask))

    ct_data = nonce + encrypted_coins          # 32 + 32 = 64 bytes
    ct = EirnCiphertext(data=ct_data, params=params)

    # Shared secret bound to ciphertext
    ss = sha3_256(b"eirn-ss" + pk_b + coins)
    return ct, ss


def Decaps(
    sk: EirnSecretKey,
    ct: EirnCiphertext,
    params: EirnParams = None,
) -> bytes:
    """
    Decapsulate: recover shared_secret from ciphertext.

    1. Derive pk from sk  (pk = H(prefix ‖ sk))
    2. Recover coins = encrypted_coins ⊕ mask
    3. Re-derive nonce' from (pk, coins) and compare with ct nonce.
       Match  → ss = H("eirn-ss" ‖ pk ‖ coins)   (valid)
       No match → ss = H("eirn-reject" ‖ sk ‖ ct)  (implicit reject)
    """
    params = params or sk.params
    ct_data = bytes(ct)
    nonce = ct_data[:32]
    encrypted_coins = ct_data[32:64]
    pk_b = sk.pk_data

    # Recompute mask from pk + nonce (same derivation as Encaps)
    mask = shake256(b"eirn-fo-mask" + pk_b + nonce, len(encrypted_coins))
    recovered_coins = bytes(a ^ b for a, b in zip(encrypted_coins, mask))

    # FO-CCA2 check: re-derive nonce and compare
    nonce_check = sha3_256(b"eirn-nonce" + pk_b + recovered_coins)

    if nonce_check == nonce:
        ss = sha3_256(b"eirn-ss" + pk_b + recovered_coins)
    else:
        ss = sha3_256(b"eirn-reject" + sk.seed + ct_data)

    return ss


def EncapsDeterministic(
    pk: EirnPublicKey,
    coins: bytes,
    params: EirnParams = None,
) -> Tuple[EirnCiphertext, bytes]:
    """Deterministic encapsulation with provided coins (for NAXOS-KEM)."""
    return Encaps(pk, params, coins=coins)
