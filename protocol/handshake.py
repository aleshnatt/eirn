"""
Eirn-KCP Handshake: MSG0' Construction and Processing.

Implements the complete handshake protocol supporting both
KcpMode.LITE (hash-based KCP) and KcpMode.STRICT (Lattice ZKPoK).

SENDER (Alice):
  1. Generate ephemeral keypair (ek_A, esk_A)
  2. Compute standard KEM encapsulations: ct1, ct2, ct3
  3. Compute NAXOS-KEM encapsulation: ct4
  4. Compute ZK proof (Lite or Strict based on kcp_mode)
  5. Form MSG0' = (pk_A, ek_A, ct1, ct2, ct3, ct4, kcp_mode, zk_proof, [lattice_pk])
  6. Derive session key

RECEIVER (Bob):
  1. Receive MSG0'
  2. Verify zk_proof (abort if invalid)  ← FAIL-FAST
  3. Decapsulate ct1, ct2, ct3, ct4
  4. Derive session key (must match Alice's)
"""

from dataclasses import dataclass
from typing import Tuple, Optional, Union

from eirn_kem.kem import (
    KeyGen, Encaps, Decaps,
    EirnPublicKey, EirnSecretKey, EirnCiphertext
)
from eirn_kem.utils import sha3_256, concat, random_bytes
from eirn_kem.params import DEFAULT_PARAMS

from naxos_kem.naxos import naxos_encaps, naxos_decaps

from zk.sigma import prove as kcp_lite_prove, verify as kcp_lite_verify, ZKProof
from lattice_zk import (
    KcpMode, derive_lattice_keys, lattice_prove, lattice_verify,
    LatticeZKProof, LatticePublicKey
)

from .prekey import PrekeyBundle
from .session import derive_session_key


class AuthenticationError(Exception):
    """Raised when ZK proof verification fails."""
    pass


@dataclass
class MSG0Prime:
    """
    Extended initial handshake message with ZK proof.
    
    Fields:
      pk_A: Alice's identity public key
      ek_A: Alice's ephemeral public key
      ct1:  Encaps(pk_B)     — identity binding
      ct2:  Encaps(spk_B)    — prekey forward secrecy
      ct3:  Encaps(opk_B)    — one-time forward secrecy
      ct4:  NAXOS.Encaps(spk_B, sk_A, esk_A, ctx) — auth
      kcp_mode: Protocol mode (LITE or STRICT)
      zk_proof: The proof (ZKProof for LITE, LatticeZKProof for STRICT)
      lattice_pk: Alice's lattice public key (STRICT mode only)
    """
    pk_A: EirnPublicKey
    ek_A: EirnPublicKey
    ct1: EirnCiphertext
    ct2: EirnCiphertext
    ct3: EirnCiphertext
    ct4: EirnCiphertext
    kcp_mode: KcpMode
    zk_proof: Union[ZKProof, LatticeZKProof]
    lattice_pk: Optional[LatticePublicKey] = None
    
    def total_size(self) -> int:
        """Compute total message size in bytes."""
        base = (
            len(bytes(self.pk_A)) +
            len(bytes(self.ek_A)) +
            len(bytes(self.ct1)) +
            len(bytes(self.ct2)) +
            len(bytes(self.ct3)) +
            len(bytes(self.ct4)) +
            1 # mode
        )
        
        proof_size = (
            self.zk_proof.proof_size() 
            if isinstance(self.zk_proof, LatticeZKProof) 
            else 96
        )
        
        lat_pk_size = len(self.lattice_pk.to_bytes()) if self.lattice_pk else 0
        
        return base + proof_size + lat_pk_size


def build_context(
    pk_A: EirnPublicKey,
    pk_B: EirnPublicKey,
    ek_A: EirnPublicKey
) -> bytes:
    """
    Build the session context for ZK proof and NAXOS-KEM.
    """
    return concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))


def sender_handshake(
    sk_A: EirnSecretKey,
    pk_A: EirnPublicKey,
    bundle_B: PrekeyBundle,
    kcp_mode: KcpMode = KcpMode.LITE
) -> Tuple[MSG0Prime, bytes]:
    """
    Alice's side of the Eirn-KCP handshake.
    Produces MSG0' and derives the session key.
    """
    pub_bundle = bundle_B.get_public_bundle()
    pk_B = pub_bundle["pk_B"]
    spk_B = pub_bundle["spk_B"]
    opk_B = pub_bundle["opk_list"][0]  # consume first OPK
    
    # Step A1: Generate ephemeral keypair
    ek_A, esk_A = KeyGen()
    
    # Build session context
    ctx = build_context(pk_A, pk_B, ek_A)
    
    # Step A2: Standard KEM encapsulations
    ct1, K1 = Encaps(pk_B)
    ct2, K2 = Encaps(spk_B)
    ct3, K3 = Encaps(opk_B)
    
    # Step A3: NAXOS-KEM
    ct4, K4 = naxos_encaps(pk_R=spk_B, sk_S=sk_A, esk_S=esk_A, context=ctx)
    
    # Step A4: ZK proof generation
    lattice_pk = None
    if kcp_mode == KcpMode.STRICT:
        lattice_pk, lattice_sk = derive_lattice_keys(bytes(sk_A))
        zk_proof = lattice_prove(lattice_sk, ctx)
        if zk_proof is None:
            raise RuntimeError("Lattice proof generation failed")
    else:
        zk_proof = kcp_lite_prove(sk_A=bytes(sk_A), pk_A=bytes(pk_A), ctx=ctx)
        
    # Step A5: Session key
    ss = derive_session_key(
        shared_secrets=[K1, K2, K3, K4],
        pk_A=bytes(pk_A),
        pk_B=bytes(pk_B),
        ek_A=bytes(ek_A),
        ciphertexts=[bytes(ct1), bytes(ct2), bytes(ct3), bytes(ct4)]
    )
    
    msg0 = MSG0Prime(
        pk_A=pk_A,
        ek_A=ek_A,
        ct1=ct1,
        ct2=ct2,
        ct3=ct3,
        ct4=ct4,
        kcp_mode=kcp_mode,
        zk_proof=zk_proof,
        lattice_pk=lattice_pk
    )
    
    return msg0, ss


def receiver_handshake(
    bundle_B: PrekeyBundle,
    msg0: MSG0Prime
) -> bytes:
    """
    Bob's side of the Eirn-KCP handshake.
    VERIFIES proof BEFORE decapsulation (fail-fast).
    """
    pk_A = msg0.pk_A
    ek_A = msg0.ek_A
    
    pk_B = bundle_B.pk_B
    sk_B = bundle_B.sk_B
    ssk_B = bundle_B.ssk_B
    osk_B = bundle_B.consume_opk()[1]
    
    ctx = build_context(pk_A, pk_B, ek_A)
    
    # VERIFY ZK proof (fail-fast)
    if msg0.kcp_mode == KcpMode.STRICT:
        if msg0.lattice_pk is None:
            raise AuthenticationError("STRICT mode requires lattice_pk")
        zk_valid = lattice_verify(msg0.lattice_pk, ctx, msg0.zk_proof)
    else:
        zk_valid = kcp_lite_verify(bytes(pk_A), ctx, msg0.zk_proof)
        
    if not zk_valid:
        raise AuthenticationError("ZK proof verification failed")
    
    # Decapsulations
    K1 = Decaps(sk_B, msg0.ct1)
    K2 = Decaps(ssk_B, msg0.ct2)
    K3 = Decaps(osk_B, msg0.ct3)
    K4 = naxos_decaps(sk_R=ssk_B, ct=msg0.ct4, pk_S=pk_A, context=ctx)
    
    # Session key derivation
    ss = derive_session_key(
        shared_secrets=[K1, K2, K3, K4],
        pk_A=bytes(pk_A),
        pk_B=bytes(pk_B),
        ek_A=bytes(ek_A),
        ciphertexts=[bytes(msg0.ct1), bytes(msg0.ct2), bytes(msg0.ct3), bytes(msg0.ct4)]
    )
    
    return ss
