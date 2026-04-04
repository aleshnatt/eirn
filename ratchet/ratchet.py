"""
Eirn-Ratchet: KEM-Ratchet Step and Receive Operations.

Implements the ratchet key rotation protocol with ZK identity binding:

  RatchetStep (sender):
    1. Generate new ephemeral keypair
    2. KEM-encapsulate to peer's last ephemeral pk
    3. Build ratchet context (binds identity + epoch + keys)
    4. Generate ZK proof binding new ek to long-term identity
    5. Update chain key with KEM shared secret
    6. Return RatchetMessage

  RatchetReceive (receiver):
    1. Verify ZK proof (FAIL-FAST — before any decapsulation)
    2. KEM-decapsulate ratchet ciphertext
    3. Update chain key
    4. Update peer's ephemeral key
"""

import hashlib
from typing import Tuple

from eirn_kem.kem import KeyGen, Encaps, Decaps, EirnPublicKey, EirnSecretKey
from eirn_kem.utils import sha3_256 as eirn_sha3_256, concat

from lattice_zk import (
    KcpMode, lattice_prove, lattice_verify,
    derive_lattice_keys, LatticeZKProof,
)
from zk.sigma import prove as kcp_lite_prove, verify as kcp_lite_verify

from .state import RatchetState, RatchetMessage


def _kdf(chain_key: bytes, shared_secret: bytes) -> bytes:
    """Derive new chain key: KDF(chain_key || K_ratchet)."""
    return hashlib.sha3_256(
        b"eirn-ratchet-kdf" + chain_key + shared_secret
    ).digest()


# ═══════════════════════════════════════════════════════════════
# Ratchet Step (Sender Side)
# ═══════════════════════════════════════════════════════════════

def ratchet_step(
    state: RatchetState,
) -> Tuple[RatchetMessage, RatchetState]:
    """
    Perform a ratchet key rotation (sender side).

    Generates a new ephemeral keypair, encapsulates to the peer's
    current ephemeral key, and proves identity binding via ZK.

    Args:
        state: Current ratchet state

    Returns:
        (RatchetMessage, updated_state)

    Raises:
        RuntimeError: If ZK proof generation fails
    """
    # ── Step 1: Generate new ephemeral keypair ──
    ek_new, esk_new = KeyGen()

    # ── Step 2: KEM encapsulate to peer's last ephemeral key ──
    ct_ratchet, K_ratchet = Encaps(state.ek_peer)

    # ── Step 3: Build ratchet context ──
    ctx = state.build_ratchet_context(ek_new, state.epoch + 1)

    # ── Step 4: Generate ZK proof binding ek_new to identity ──
    if state.kcp_mode == KcpMode.STRICT:
        # Lattice-native ZKPoK
        if state.lattice_sk is None:
            # Derive lattice keys on first use
            state.lattice_pk, state.lattice_sk = derive_lattice_keys(
                bytes(state.identity_sk)
            )
        proof = lattice_prove(state.lattice_sk, ctx)
        if proof is None:
            raise RuntimeError(
                "Lattice ZK proof generation failed "
                "(exceeded max rejection sampling attempts)"
            )
    else:
        # KCP-Lite (hash-based)
        proof = kcp_lite_prove(
            sk_A=bytes(state.identity_sk),
            pk_A=bytes(state.identity_pk),
            ctx=ctx,
        )

    # ── Step 5: Update chain key ──
    new_chain_key = _kdf(state.chain_key, K_ratchet)

    # ── Step 6: Build message ──
    msg = RatchetMessage(
        ek_new=ek_new,
        ct_ratchet=ct_ratchet,
        epoch=state.epoch + 1,
        zk_proof=proof,
        kcp_mode=state.kcp_mode,
    )

    # ── Step 7: Update state (erase old esk in production) ──
    new_state = RatchetState(
        identity_pk=state.identity_pk,
        identity_sk=state.identity_sk,
        lattice_pk=state.lattice_pk,
        lattice_sk=state.lattice_sk,
        ek_self=ek_new,
        esk_self=esk_new,
        ek_peer=state.ek_peer,
        chain_key=new_chain_key,
        epoch=state.epoch + 1,
        kcp_mode=state.kcp_mode,
    )

    return msg, new_state


# ═══════════════════════════════════════════════════════════════
# Ratchet Receive (Receiver Side)
# ═══════════════════════════════════════════════════════════════

class RatchetAuthError(Exception):
    """Raised when a ratchet ZK proof fails verification."""
    pass


def ratchet_receive(
    state: RatchetState,
    msg: RatchetMessage,
    peer_identity_pk: EirnPublicKey,
    peer_lattice_pk=None,
) -> RatchetState:
    """
    Process a received ratchet message (receiver side).

    FAIL-FAST: ZK proof is verified BEFORE any KEM decapsulation.

    Args:
        state: Current ratchet state
        msg: Received ratchet message
        peer_identity_pk: Peer's long-term identity public key
        peer_lattice_pk: Peer's lattice public key (for STRICT mode)

    Returns:
        Updated ratchet state

    Raises:
        RatchetAuthError: If ZK proof verification fails
    """
    # ── Step 0: Epoch sequencing check ──
    if msg.epoch != state.epoch + 1:
        raise RatchetAuthError(
            f"Epoch mismatch: expected {state.epoch + 1}, got {msg.epoch}"
        )

    # ── Step 1: Build ratchet context (must match sender's) ──
    # The sender used: ctx = H(pk_identity || ek_prev_sender || ek_new || epoch)
    # From receiver's view, ek_prev_sender = state.ek_peer
    epoch_bytes = msg.epoch.to_bytes(4, 'little')
    ek_prev_bytes = bytes(state.ek_peer) if state.ek_peer else b"\x00" * 32

    ctx = hashlib.sha3_256(
        bytes(peer_identity_pk) +
        ek_prev_bytes +
        bytes(msg.ek_new) +
        epoch_bytes
    ).digest()

    # ── Step 2: VERIFY ZK PROOF (fail-fast) ──
    if msg.kcp_mode == KcpMode.STRICT:
        if peer_lattice_pk is None:
            raise RatchetAuthError(
                "STRICT mode requires peer's lattice public key"
            )
        valid = lattice_verify(peer_lattice_pk, ctx, msg.zk_proof)
    else:
        valid = kcp_lite_verify(
            pk_A=bytes(peer_identity_pk),
            ctx=ctx,
            proof=msg.zk_proof,
        )

    if not valid:
        raise RatchetAuthError(
            "Ratchet ZK proof verification failed: "
            "identity binding broken. Possible ratchet hijack attempt."
        )

    # ── Step 3: KEM decapsulate (only after ZK passes) ──
    K_ratchet = Decaps(state.esk_self, msg.ct_ratchet)

    # ── Step 4: Update chain key ──
    new_chain_key = _kdf(state.chain_key, K_ratchet)

    # ── Step 5: Update state ──
    new_state = RatchetState(
        identity_pk=state.identity_pk,
        identity_sk=state.identity_sk,
        lattice_pk=state.lattice_pk,
        lattice_sk=state.lattice_sk,
        ek_self=state.ek_self,
        esk_self=state.esk_self,
        ek_peer=msg.ek_new,     # Update peer's ek to the new one
        chain_key=new_chain_key,
        epoch=msg.epoch,
        kcp_mode=state.kcp_mode,
    )

    return new_state
