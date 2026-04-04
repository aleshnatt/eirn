"""
Ratchet State Machine and Message Structures.

Defines the state maintained by each party during a ratcheted session
and the message format for ratchet key rotations.

The ratchet ensures:
  1. Post-compromise security: each new key pair provides fresh randomness
  2. Forward secrecy: old keys are erased after rotation
  3. Identity continuity: each rotation is proven bound to the long-term identity

State Evolution:
  epoch 0: Handshake establishes initial chain_key and ephemeral keys
  epoch n: New (ek, esk) generated, KEM encapsulated to peer's last ek,
           chain_key updated with KEM shared secret, ZK proof binds
           new ek to identity
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional, Union

from eirn_kem.kem import EirnPublicKey, EirnSecretKey, EirnCiphertext
from lattice_zk import (
    LatticeZKProof, LatticePublicKey, LatticeSecretKey, KcpMode,
)
from zk.sigma import ZKProof


def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


# ═══════════════════════════════════════════════════════════════
# Ratchet State
# ═══════════════════════════════════════════════════════════════

@dataclass
class RatchetState:
    """
    Per-session ratchet state maintained by each party.

    This state is mutable: it updates with each ratchet step.
    Old ephemeral secret keys MUST be erased after rotation
    (zeroized in production).
    """
    # ── Identity (fixed for session lifetime) ──
    identity_pk: EirnPublicKey      # Our long-term public key
    identity_sk: EirnSecretKey      # Our long-term secret key

    # ── Lattice ZK keys (derived from identity_sk) ──
    lattice_pk: Optional[LatticePublicKey] = None
    lattice_sk: Optional[LatticeSecretKey] = None

    # ── Current ephemeral keys (rotate each step) ──
    ek_self: Optional[EirnPublicKey] = None     # Our current ephemeral pk
    esk_self: Optional[EirnSecretKey] = None    # Our current ephemeral sk
    ek_peer: Optional[EirnPublicKey] = None     # Peer's current ephemeral pk

    # ── Symmetric state ──
    chain_key: bytes = b"\x00" * 32     # 32-byte symmetric chain key
    epoch: int = 0                       # Ratchet epoch counter

    # ── Mode selection ──
    kcp_mode: KcpMode = KcpMode.STRICT

    def build_ratchet_context(
        self,
        ek_new: EirnPublicKey,
        epoch: int,
    ) -> bytes:
        """
        Build the ratchet context for ZK proof binding.

        Per architectural decision:
          ctx = SHA3-256(pk_identity || ek_prev || ek_new || epoch)

        This ensures:
          - Identity binding (pk_identity)
          - Chain continuity (ek_prev)
          - Key freshness (ek_new)
          - Epoch sequencing (epoch)
        """
        epoch_bytes = epoch.to_bytes(4, 'little')
        ek_prev_bytes = bytes(self.ek_self) if self.ek_self else b"\x00" * 32

        return _sha3_256(
            bytes(self.identity_pk) +
            ek_prev_bytes +
            bytes(ek_new) +
            epoch_bytes
        )


# ═══════════════════════════════════════════════════════════════
# Ratchet Message
# ═══════════════════════════════════════════════════════════════

@dataclass
class RatchetMessage:
    """
    Message sent during a ratchet key rotation.

    Fields:
      ek_new:     New ephemeral public key (sender's fresh key)
      ct_ratchet: KEM ciphertext encapsulated to peer's last ek
      epoch:      Ratchet epoch counter
      zk_proof:   Identity-bound proof (LatticeZKProof or ZKProof)
      kcp_mode:   Which proof mode was used
    """
    ek_new: EirnPublicKey
    ct_ratchet: EirnCiphertext
    epoch: int
    zk_proof: Union[LatticeZKProof, ZKProof]
    kcp_mode: KcpMode

    def total_size(self) -> int:
        """Compute total ratchet message size."""
        proof_size = (
            self.zk_proof.proof_size()
            if isinstance(self.zk_proof, LatticeZKProof)
            else 96  # ZKProof is always 96 bytes
        )
        return (
            len(bytes(self.ek_new)) +
            len(bytes(self.ct_ratchet)) +
            4 +  # epoch (u32)
            proof_size
        )
