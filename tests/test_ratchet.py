"""
Test Suite for Eirn-Ratchet.

Verifies the ratchet key rotation protocol, including the
lattice ZK identity binding.
"""

import pytest
from eirn_kem.kem import KeyGen
from ratchet import RatchetState, ratchet_step, ratchet_receive, RatchetMessage
from ratchet.ratchet import RatchetAuthError
from lattice_zk import KcpMode

def test_ratchet_roundtrip_strict():
    """Test a full ratchet step + receive in STRICT mode (Lattice ZK)."""
    # ── Setup initial keys ──
    pk_A, sk_A = KeyGen()
    pk_B, sk_B = KeyGen()
    
    ek_A, esk_A = KeyGen()
    ek_B, esk_B = KeyGen()
    
    initial_chain_key = b"initial-chain-key-1234567890123"
    
    # ── Initialize State ──
    state_A = RatchetState(
        identity_pk=pk_A,
        identity_sk=sk_A,
        ek_self=ek_A,
        esk_self=esk_A,
        ek_peer=ek_B,
        chain_key=initial_chain_key,
        epoch=0,
        kcp_mode=KcpMode.STRICT,
    )
    
    state_B = RatchetState(
        identity_pk=pk_B,
        identity_sk=sk_B,
        ek_self=ek_B,
        esk_self=esk_B,
        ek_peer=ek_A,
        chain_key=initial_chain_key,
        epoch=0,
        kcp_mode=KcpMode.STRICT,
    )

    # ── Alice performs Ratchet Step ──
    msg, new_state_A = ratchet_step(state_A)

    assert msg.epoch == 1
    assert msg.kcp_mode == KcpMode.STRICT
    assert new_state_A.ek_self == msg.ek_new
    assert new_state_A.chain_key != initial_chain_key

    # Bob needs Alice's lattice_pk for STRICT mode verification
    peer_lattice_pk = new_state_A.lattice_pk

    # ── Bob receives Ratchet Message ──
    new_state_B = ratchet_receive(
        state=state_B,
        msg=msg,
        peer_identity_pk=pk_A,
        peer_lattice_pk=peer_lattice_pk
    )

    # ── Assertions ──
    assert new_state_A.chain_key == new_state_B.chain_key, "Chain keys must match"
    assert new_state_B.epoch == 1
    assert new_state_B.ek_peer == msg.ek_new


def test_ratchet_mitm_hijack():
    """Test that a MITM trying to hijack the ratchet is rejected."""
    pk_A, sk_A = KeyGen()
    pk_B, sk_B = KeyGen()
    pk_M, sk_M = KeyGen()  # MITM
    
    ek_A, esk_A = KeyGen()
    ek_B, esk_B = KeyGen()
    
    initial_chain_key = b"initial-chain-key-1234567890123"
    
    # MITM state (pretending to be Alice)
    state_M = RatchetState(
        identity_pk=pk_M,   # MITM's own identity
        identity_sk=sk_M,
        ek_self=ek_A,
        esk_self=esk_A,
        ek_peer=ek_B,
        chain_key=initial_chain_key,
        epoch=0,
        kcp_mode=KcpMode.STRICT,
    )
    
    state_B = RatchetState(
        identity_pk=pk_B,
        identity_sk=sk_B,
        ek_self=ek_B,
        esk_self=esk_B,
        ek_peer=ek_A,
        chain_key=initial_chain_key,
        epoch=0,
        kcp_mode=KcpMode.STRICT,
    )

    # MITM generates a ratchet message
    msg, _ = ratchet_step(state_M)

    # Bob verifies it, thinking it's from Alice
    with pytest.raises(RatchetAuthError):
        ratchet_receive(
            state=state_B,
            msg=msg,
            peer_identity_pk=pk_A,      # Bob thinks it's from Alice
            peer_lattice_pk=None        # Mismatch happens here or via context
        )
