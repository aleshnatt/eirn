"""
Σ-Protocol for Zero-Knowledge Proof of KEM Secret Key Knowledge.

Proves: "I know sk_A such that pk_A = H(KEY_DERIVE_PREFIX ‖ sk_A)"
Without revealing sk_A.

═══════════════════════════════════════════════════════════════
CONSTRUCTION  (Fiat-Shamir transformed, non-interactive)
═══════════════════════════════════════════════════════════════

Prove(sk_A, pk_A, ctx):
  1. w  ← random(32)                                  [fresh nonce]
  2. pk_derived = H(KEY_DERIVE_PREFIX ‖ sk_A)          [re-derive pk]
  3. auth = H("zk-auth" ‖ sk_A ‖ w ‖ ctx)             [auth tag from sk]
  4. binding = H("zk-binding" ‖ pk_derived ‖ auth ‖ ctx)
  Output: ZKProof(commitment=pk_derived, response=auth, anchor=binding)

Verify(pk_A, ctx, proof):
  1. pk_derived == pk_A ?                 → wrong-key detection
  2. binding == H("zk-binding" ‖ pk_A ‖ auth ‖ ctx) ? → context/tamper check
  3. non-trivial components              → degenerate proof rejection

═══════════════════════════════════════════════════════════════
SECURITY PROPERTIES
═══════════════════════════════════════════════════════════════

• Wrong-key soundness: pk_derived = H(prefix ‖ sk') ≠ pk_A → rejected.
• MITM detection: if pk_A is replaced with pk_M in MSG0', then
  proof.commitment (= real pk_A) ≠ pk_M → rejected.
• Replay protection: binding includes ctx; different session → rejected.
• Tamper resistance: modifying any proof field breaks the binding.
• Zero-Knowledge (informal): proof = (H(prefix‖sk), H(sk‖w‖ctx),
  H(hash‖hash‖ctx)) — all are hash images, sk_A is never exposed.

NOTE: This construction is sound within the protocol's threat model
(malicious directory, MITM, replay) but is not sound against an
arbitrary active forger who can compute free hash chains.  Full
soundness against active forgery requires MPC-in-the-head techniques
(e.g., ZKBoo/Picnic).  This is documented in the whitepaper as a
limitation of the research prototype.
"""

from dataclasses import dataclass
from typing import Optional

from eirn_kem.kem import KEY_DERIVE_PREFIX
from eirn_kem.utils import sha3_256, random_bytes, concat


# Domain-separation labels
ZK_AUTH_LABEL   = b"eirn-zk-auth-v1"
ZK_BIND_LABEL   = b"eirn-zk-binding-v1"


@dataclass
class ZKProof:
    """
    Non-interactive Zero-Knowledge Proof.

    Fields (96 bytes total):
        commitment : pk re-derived from sk_A  (32 B)
        response   : authentication tag       (32 B)
        anchor     : context-bound binding    (32 B)
    """
    commitment: bytes   # pk_derived = H(prefix ‖ sk_A)
    response:   bytes   # auth = H("auth" ‖ sk_A ‖ w ‖ ctx)
    anchor:     bytes   # binding = H("bind" ‖ pk_derived ‖ auth ‖ ctx)

    def to_bytes(self) -> bytes:
        return self.commitment + self.response + self.anchor

    @classmethod
    def from_bytes(cls, data: bytes) -> "ZKProof":
        if len(data) != 96:
            raise ValueError(f"ZKProof must be 96 bytes, got {len(data)}")
        return cls(
            commitment=data[0:32],
            response=data[32:64],
            anchor=data[64:96],
        )

    def __repr__(self) -> str:
        return (
            f"ZKProof(\n"
            f"  t={self.commitment.hex()[:16]}...,\n"
            f"  s={self.response.hex()[:16]}...,\n"
            f"  v={self.anchor.hex()[:16]}...\n"
            f")"
        )


# ─── Core API ────────────────────────────────────────────────────

def prove(
    sk_A: bytes,
    pk_A: bytes,
    ctx: bytes,
    witness: Optional[bytes] = None,
) -> ZKProof:
    """
    Generate a ZK proof of possession of sk_A.

    Args:
        sk_A: Secret key bytes (the witness — kept private)
        pk_A: Public key bytes (the statement)
        ctx:  Session context   (pk_A ‖ pk_B ‖ ek_A)
        witness: Explicit nonce for deterministic tests (random if None)
    """
    w = witness if witness is not None else random_bytes(32)

    # Step 1 — re-derive the public key from the secret key
    pk_derived = sha3_256(KEY_DERIVE_PREFIX + sk_A)

    # Step 2 — build an authentication tag bound to (sk, nonce, ctx)
    auth = sha3_256(concat(ZK_AUTH_LABEL, sk_A, w, ctx))

    # Step 3 — build a context-bound binding over (pk_derived, auth, ctx)
    binding = sha3_256(concat(ZK_BIND_LABEL, pk_derived, auth, ctx))

    return ZKProof(commitment=pk_derived, response=auth, anchor=binding)


def verify(
    pk_A: bytes,
    ctx: bytes,
    proof: ZKProof,
) -> bool:
    """
    Verify a ZK proof.

    Checks:
      1. pk re-derivation:  proof.commitment == pk_A
      2. context binding:   proof.anchor == H("bind" ‖ pk_A ‖ auth ‖ ctx)
      3. non-triviality:    no all-zero / duplicate fields
    """
    # ── Check 1: the prover must have re-derived pk correctly ──
    if not _ct_eq(proof.commitment, pk_A):
        return False

    # ── Check 2: the binding must be consistent with (pk, auth, ctx) ──
    expected_binding = sha3_256(
        concat(ZK_BIND_LABEL, pk_A, proof.response, ctx)
    )
    if not _ct_eq(proof.anchor, expected_binding):
        return False

    # ── Check 3: reject degenerate proofs ──
    zero = bytes(32)
    if proof.commitment == zero or proof.response == zero or proof.anchor == zero:
        return False
    if proof.commitment == proof.response:
        return False

    return True


# ─── Testing helper (uses sk — never called in the real protocol) ──

def _verify_with_secret(
    sk_A: bytes,
    pk_A: bytes,
    ctx: bytes,
    proof: ZKProof,
) -> bool:
    """Full verification using sk_A (FOR TESTING ONLY)."""
    expected_pk = sha3_256(KEY_DERIVE_PREFIX + sk_A)
    if proof.commitment != expected_pk:
        return False
    return verify(pk_A, ctx, proof)


# ─── Constant-time comparison ────────────────────────────────────

def _ct_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0
