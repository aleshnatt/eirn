#!/usr/bin/env python3
"""
Eirn-KCP: In-Band Key Consistency for Post-Quantum AKE
Protocol simulation with verbose debug logging.
"""

import sys
import time
from dataclasses import dataclass
from typing import Tuple

from eirn_kem.kem import KeyGen, KEY_DERIVE_PREFIX
from eirn_kem.utils import random_bytes, concat, sha3_256
from eirn_kem.params import PARAMS_512
from protocol.prekey import generate_prekey_bundle
from protocol.handshake import (
    sender_handshake, receiver_handshake,
    AuthenticationError, build_context
)
from zk.sigma import prove, verify, ZKProof


# ─── Debug Levels (Mbed TLS style) ───────────────────────────────
#
#   0 = No output
#   1 = Error messages only
#   2 = State changes
#   3 = Informational
#   4 = Verbose (full hex dumps, internal values)

DEBUG_LEVEL = 4


def _log(level: int, component: str, msg: str):
    if level <= DEBUG_LEVEL:
        tags = {1: "ERROR", 2: "STATE", 3: "INFO ", 4: "DEBUG"}
        tag = tags.get(level, "     ")
        print(f"  [{tag}] {component}: {msg}")


def _hex(data: bytes) -> str:
    return data.hex()


def _dump(level: int, component: str, label: str, data: bytes):
    if level <= DEBUG_LEVEL:
        _log(level, component, f"{label} = {_hex(data)} ({len(data)} bytes)")


# ─── Protocol Simulation ─────────────────────────────────────────

def run_handshake():
    """Scenario 1: Normal handshake with verbose logging."""
    print("\nEirn-KCP Handshake Simulation (debug_level=4) \n")

    # ── Alice: Identity KeyGen ──
    _log(2, "alice", "generating identity keypair (Eirn-KEM KeyGen)")
    pk_A, sk_A = KeyGen(PARAMS_512)
    _dump(3, "alice", "sk_A.seed", sk_A.seed)
    _dump(3, "alice", "pk_A.data", pk_A.data)
    _log(4, "alice", f"pk_A derived via SHA3-256(\"{KEY_DERIVE_PREFIX.decode()}\" || sk_A)")
    _log(4, "alice", f"params: {PARAMS_512.name}, n={PARAMS_512.n}, k={PARAMS_512.k}, q={PARAMS_512.q}")

    # ── Bob: Prekey Bundle ──
    _log(2, "bob  ", "generating prekey bundle")
    bundle_B = generate_prekey_bundle(num_opk=5, params=PARAMS_512)
    _dump(3, "bob  ", "pk_B.data ", bundle_B.pk_B.data)
    _dump(3, "bob  ", "spk_B.data", bundle_B.spk_B.data)
    _dump(4, "bob  ", "com_B     ", bundle_B.com_B)
    _log(3, "bob  ", f"one-time prekeys generated: {len(bundle_B.opk_list)}")
    for i, (opk, _) in enumerate(bundle_B.opk_list):
        _dump(4, "bob  ", f"opk_B[{i}]  ", opk.data)

    # ── Alice: Sender Handshake ──
    _log(2, "alice", "initiating sender handshake")
    t0 = time.perf_counter()

    # Step-by-step (manual expansion for logging)
    _log(3, "alice", "step A1: generating ephemeral keypair")
    ek_A, esk_A = KeyGen(PARAMS_512)
    _dump(4, "alice", "ek_A.data ", ek_A.data)
    _dump(4, "alice", "esk_A.seed", esk_A.seed)

    pub_bundle = bundle_B.get_public_bundle()
    pk_B = pub_bundle["pk_B"]
    spk_B = pub_bundle["spk_B"]
    opk_B = pub_bundle["opk_list"][0]

    ctx = build_context(pk_A, pk_B, ek_A)
    _dump(4, "alice", "ctx       ", ctx)

    _log(3, "alice", "step A2: KEM encapsulations (ct1, ct2, ct3)")
    from eirn_kem.kem import Encaps
    ct1, K1 = Encaps(pk_B)
    _dump(4, "alice", "ct1.data  ", ct1.data)
    _dump(4, "alice", "K1        ", K1)

    ct2, K2 = Encaps(spk_B)
    _dump(4, "alice", "ct2.data  ", ct2.data)
    _dump(4, "alice", "K2        ", K2)

    ct3, K3 = Encaps(opk_B)
    _dump(4, "alice", "ct3.data  ", ct3.data)
    _dump(4, "alice", "K3        ", K3)

    _log(3, "alice", "step A3: NAXOS-KEM encapsulation (ct4)")
    from naxos_kem.naxos import naxos_encaps, naxos_derive_coins
    r_nax = naxos_derive_coins(sk_A, esk_A, spk_B, ctx)
    _dump(4, "alice", "r_nax     ", r_nax)
    _log(4, "alice", "r_nax = SHA3-256(sk_A || H(esk_A) || spk_B || ctx || label)")
    ct4, K4 = naxos_encaps(spk_B, sk_A, esk_A, ctx)
    _dump(4, "alice", "ct4.data  ", ct4.data)
    _dump(4, "alice", "K4        ", K4)

    _log(3, "alice", "step A4: generating ZK proof")
    _log(4, "alice", "ZK.Prove(sk_A, pk_A, ctx)")
    zk_proof = prove(bytes(sk_A), bytes(pk_A), ctx)
    _dump(4, "alice", "proof.C   ", zk_proof.commitment)
    _dump(4, "alice", "proof.R   ", zk_proof.response)
    _dump(4, "alice", "proof.B   ", zk_proof.anchor)
    _log(4, "alice", f"proof.C == pk_A ? {zk_proof.commitment == pk_A.data}")
    _log(3, "alice", f"proof size: {len(zk_proof.to_bytes())} bytes")

    _log(3, "alice", "step A5: deriving session key")
    from protocol.session import derive_session_key
    ss_alice = derive_session_key(
        [K1, K2, K3, K4],
        bytes(pk_A), bytes(pk_B), bytes(ek_A),
        [bytes(ct1), bytes(ct2), bytes(ct3), bytes(ct4)]
    )
    _dump(3, "alice", "SS_alice  ", ss_alice)

    t_sender = time.perf_counter() - t0
    _log(3, "alice", f"sender handshake completed in {t_sender*1000:.3f} ms")

    # ── Construct MSG0' ──
    from protocol.handshake import MSG0Prime
    from lattice_zk import KcpMode
    msg0 = MSG0Prime(pk_A=pk_A, ek_A=ek_A, ct1=ct1, ct2=ct2,
                     ct3=ct3, ct4=ct4, kcp_mode=KcpMode.LITE, zk_proof=zk_proof)
    _log(2, "wire ", f"MSG0' assembled, total {msg0.total_size()} bytes")
    _dump(4, "wire ", "  pk_A    ", pk_A.data)
    _dump(4, "wire ", "  ek_A    ", ek_A.data)
    _dump(4, "wire ", "  ct1     ", ct1.data)
    _dump(4, "wire ", "  ct2     ", ct2.data)
    _dump(4, "wire ", "  ct3     ", ct3.data)
    _dump(4, "wire ", "  ct4     ", ct4.data)
    _dump(4, "wire ", "  proof   ", zk_proof.to_bytes())

    # ── Bob: Receiver Handshake ──
    _log(2, "bob  ", "processing received MSG0'")
    t0 = time.perf_counter()

    _log(3, "bob  ", "step B1: reconstructing context")
    ctx_bob = build_context(msg0.pk_A, bundle_B.pk_B, msg0.ek_A)
    _dump(4, "bob  ", "ctx       ", ctx_bob)

    _log(3, "bob  ", "step B2: verifying ZK proof")
    _log(4, "bob  ", f"ZK.Verify(pk_A={_hex(msg0.pk_A.data)}, ctx, proof)")
    _log(4, "bob  ", f"check 1: proof.C == pk_A ? {msg0.zk_proof.commitment == msg0.pk_A.data}")

    expected_binding = sha3_256(concat(
        b"eirn-zk-binding-v1", msg0.pk_A.data,
        msg0.zk_proof.response, ctx_bob
    ))
    _log(4, "bob  ", f"check 2: proof.B == H(bind||pk_A||R||ctx) ? {msg0.zk_proof.anchor == expected_binding}")

    zk_ok = verify(bytes(msg0.pk_A), ctx_bob, msg0.zk_proof)
    if zk_ok:
        _log(2, "bob  ", "key consistency check: PASS")
    else:
        _log(1, "bob  ", "key consistency check: FAIL — aborting")
        return

    _log(3, "bob  ", "step B3: KEM decapsulations")
    from eirn_kem.kem import Decaps
    opk_consumed, osk_consumed = bundle_B.consume_opk()

    K1_bob = Decaps(bundle_B.sk_B, msg0.ct1)
    _dump(4, "bob  ", "K1        ", K1_bob)
    K2_bob = Decaps(bundle_B.ssk_B, msg0.ct2)
    _dump(4, "bob  ", "K2        ", K2_bob)
    K3_bob = Decaps(osk_consumed, msg0.ct3)
    _dump(4, "bob  ", "K3        ", K3_bob)

    _log(3, "bob  ", "step B4: NAXOS-KEM decapsulation")
    from naxos_kem.naxos import naxos_decaps
    K4_bob = naxos_decaps(bundle_B.ssk_B, msg0.ct4, msg0.pk_A, ctx_bob)
    _dump(4, "bob  ", "K4        ", K4_bob)

    _log(3, "bob  ", "step B5: deriving session key")
    ss_bob = derive_session_key(
        [K1_bob, K2_bob, K3_bob, K4_bob],
        bytes(msg0.pk_A), bytes(bundle_B.pk_B), bytes(msg0.ek_A),
        [bytes(msg0.ct1), bytes(msg0.ct2), bytes(msg0.ct3), bytes(msg0.ct4)]
    )
    _dump(3, "bob  ", "SS_bob    ", ss_bob)

    t_recv = time.perf_counter() - t0
    _log(3, "bob  ", f"receiver handshake completed in {t_recv*1000:.3f} ms")

    # ── Session key comparison ──
    if ss_alice == ss_bob:
        _log(2, "proto", f"session keys MATCH: {_hex(ss_alice)}")
    else:
        _log(1, "proto", "session key MISMATCH")
        _dump(1, "proto", "SS_alice", ss_alice)
        _dump(1, "proto", "SS_bob  ", ss_bob)

    print()


def run_invalid_proof():
    """Scenario 2: Tampered proof rejection."""
    print("Eirn-KCP Tampered Proof (debug_level=4) \n")

    pk_A, sk_A = KeyGen()
    bundle_B = generate_prekey_bundle(num_opk=5)

    _log(2, "alice", "generating MSG0' with valid proof")
    msg0, _ = sender_handshake(sk_A, pk_A, bundle_B)
    _dump(4, "alice", "proof.C   ", msg0.zk_proof.commitment)

    _log(2, "mitm ", "replacing proof with random bytes")
    msg0.zk_proof = ZKProof(
        commitment=random_bytes(32),
        response=random_bytes(32),
        anchor=random_bytes(32)
    )
    _dump(4, "mitm ", "forged.C  ", msg0.zk_proof.commitment)

    _log(2, "bob  ", "processing tampered MSG0'")
    _log(4, "bob  ", f"check 1: proof.C == pk_A ? {msg0.zk_proof.commitment == pk_A.data}")
    try:
        receiver_handshake(bundle_B, msg0)
        _log(1, "bob  ", "CRITICAL: tampered proof accepted")
    except AuthenticationError as e:
        _log(2, "bob  ", "ZK proof verification: FAIL — correctly rejected")
        _log(4, "bob  ", f"reason: {e}")

    print()


def run_mitm():
    """Scenario 3: MITM key substitution detection."""
    print("Eirn-KCP MITM Detection (debug_level=4) \n")

    pk_A, sk_A = KeyGen()
    pk_M, sk_M = KeyGen()
    bundle_B = generate_prekey_bundle(num_opk=5)

    _dump(3, "alice", "pk_A     ", pk_A.data)
    _dump(3, "mitm ", "pk_M     ", pk_M.data)

    _log(2, "alice", "generating MSG0' with proof bound to pk_A")
    msg0, _ = sender_handshake(sk_A, pk_A, bundle_B)

    _log(2, "mitm ", "intercepting MSG0': replacing pk_A with pk_M")
    msg0.pk_A = pk_M
    _log(4, "mitm ", f"MSG0'.pk_A now = {_hex(pk_M.data)}")
    _log(4, "mitm ", f"but proof.C    = {_hex(msg0.zk_proof.commitment)}")

    _log(2, "bob  ", "processing modified MSG0'")
    _log(4, "bob  ", f"check 1: proof.C == pk_M ? {msg0.zk_proof.commitment == pk_M.data}")
    try:
        receiver_handshake(bundle_B, msg0)
        _log(1, "bob  ", "CRITICAL: MITM succeeded")
    except AuthenticationError:
        _log(2, "bob  ", "ZK proof verification: FAIL — MITM detected")

    print()


def run_malicious_directory():
    """Scenario 4: Malicious directory server detection."""
    print("Eirn-KCP Malicious Directory (debug_level=4) \n")

    pk_A, sk_A = KeyGen()
    pk_M, sk_M = KeyGen()

    _dump(3, "dir  ", "real pk_A ", pk_A.data)
    _log(2, "dir  ", "directory substitutes pk_A -> pk_M")
    _dump(3, "dir  ", "fake pk_M ", pk_M.data)

    bundle_B = generate_prekey_bundle(num_opk=5)
    _log(2, "alice", "generating MSG0' with real sk_A")
    msg0, _ = sender_handshake(sk_A, pk_A, bundle_B)
    _log(4, "alice", f"proof.C = H(prefix || sk_A) = pk_A = {_hex(pk_A.data)}")

    _log(2, "bob  ", "retrieved pk_M from compromised directory")
    msg0.pk_A = pk_M
    _log(4, "bob  ", f"using pk_M = {_hex(pk_M.data)} as sender identity")

    try:
        receiver_handshake(bundle_B, msg0)
        _log(1, "bob  ", "CRITICAL: directory attack succeeded")
    except AuthenticationError:
        _log(2, "bob  ", "ZK proof verification: FAIL — directory compromise detected")
        _log(3, "bob  ", f"proof.C ({_hex(msg0.zk_proof.commitment)}) != pk_M ({_hex(pk_M.data)})")

    print()


def run_replay():
    """Scenario 5: Replay to different receiver."""
    print("Eirn-KCP Replay Detection (debug_level=4) \n")

    pk_A, sk_A = KeyGen()
    bundle_B1 = generate_prekey_bundle(num_opk=5)
    bundle_B2 = generate_prekey_bundle(num_opk=5)

    _dump(3, "proto", "pk_B1     ", bundle_B1.pk_B.data)
    _dump(3, "proto", "pk_B2     ", bundle_B2.pk_B.data)

    _log(2, "alice", "sending MSG0' to Bob1")
    msg0, _ = sender_handshake(sk_A, pk_A, bundle_B1)
    ctx1 = build_context(pk_A, bundle_B1.pk_B, msg0.ek_A)
    _dump(4, "alice", "ctx(B1)   ", ctx1)

    _log(2, "mitm ", "replaying MSG0' to Bob2")
    ctx2 = build_context(pk_A, bundle_B2.pk_B, msg0.ek_A)
    _dump(4, "mitm ", "ctx(B2)   ", ctx2)
    _log(4, "mitm ", f"ctx1 == ctx2 ? {ctx1 == ctx2}")

    try:
        receiver_handshake(bundle_B2, msg0)
        _log(1, "bob2 ", "CRITICAL: replay succeeded")
    except AuthenticationError:
        _log(2, "bob2 ", "ZK proof verification: FAIL — replay detected (context mismatch)")

    print()


def run_benchmarks():
    """Performance measurements."""
    print("Eirn-KCP Benchmarks\n")

    N = 100
    pk_A, sk_A = KeyGen()
    pk_B, _ = KeyGen()
    ek_A, _ = KeyGen()
    ctx = concat(bytes(pk_A), bytes(pk_B), bytes(ek_A))

    t0 = time.perf_counter()
    for _ in range(N):
        p = prove(bytes(sk_A), bytes(pk_A), ctx)
    t_prove = (time.perf_counter() - t0) / N

    t0 = time.perf_counter()
    for _ in range(N):
        verify(bytes(pk_A), ctx, p)
    t_verify = (time.perf_counter() - t0) / N

    sender_t, recv_t = [], []
    for _ in range(N):
        b = generate_prekey_bundle(num_opk=1)
        t1 = time.perf_counter()
        m, _ = sender_handshake(sk_A, pk_A, b)
        sender_t.append(time.perf_counter() - t1)
        t2 = time.perf_counter()
        try:
            receiver_handshake(b, m)
        except Exception:
            pass
        recv_t.append(time.perf_counter() - t2)

    _log(3, "bench", f"iterations: {N}")
    _log(3, "bench", f"KCP.Prove          : {t_prove*1000:.4f} ms")
    _log(3, "bench", f"KCP.Verify         : {t_verify*1000:.4f} ms")
    _log(3, "bench", f"sender handshake   : {sum(sender_t)/N*1000:.4f} ms")
    _log(3, "bench", f"receiver handshake : {sum(recv_t)/N*1000:.4f} ms")

    print()


# ─── Main ─────────────────────────────────────────────────────────

def main():
    run_handshake()
    run_invalid_proof()
    run_mitm()
    run_malicious_directory()
    run_replay()
    run_benchmarks()


if __name__ == "__main__":
    main()
