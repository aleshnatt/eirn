# Eirn-KCP: Continuous Identity Binding via Lattice-Native Zero-Knowledge Proofs for Post-Quantum AKE

> **Cryptographic Construction, Protocol Extension, and Formal Security Analysis** — Extending Eirn-AKE to eliminate out-of-band Trust-On-First-Use (TOFU) verification natively.

## Overview

Eirn-AKE is a pure-lattice asynchronous Authenticated Key Exchange protocol built over Module-LWE, securely exchanging keys via NAXOS-KEM. However, it relies heavily on out-of-band (OOB) identity verification to defend against malicious directory servers performing key substitution attacks.

**Eirn-KCP** solves this limitation by integrating a \textit{Key Consistency Proof (KCP)} directly into the handshake and continuous session epochs. The protocol is structured as a dual-mode cipher suite to accommodate diverse network constraints:

1. **Eirn-KCP-Hash**: A lightweight 96-byte hash-based consistency proof. It acts as a highly efficient fail-fast filter, granting \textbf{wrong-key soundness} against generic substitution attacks prior to demanding heavy NTT matrix decapsulations. 
2. **Eirn-KCP-Lattice**: A full $\sim 1.3$ KB Lattice-Native Zero-Knowledge Proof of Knowledge (ZKPoK). Constructed natively over the Module-LWE relationship via Lyubashevsky's Rejection Sampling, it yields strict Structural Witness Extraction and Honest-Verifier Zero-Knowledge (HVZK) against highly active adversarial forging.

### Feature Comparison

| Feature | Base Eirn-AKE | Eirn-KCP-Hash | Eirn-KCP-Lattice |
|---------|---------------|----------|------------|
| Authentication | NAXOS-KEM (implicit) | Hash-based Consistency| Lattice ZKPoK |
| Identity Verification | Out-of-band (TOFU) | In-band | In-band, strictly formal |
| Proof Construct | None | Fiat-Shamir Simulation | MLWE Rejection Sampling |
| Data Overhead | None | + 96 Bytes | + $\sim 1.3$ KB |
| DoS System Resilience | 4× Decaps to fail | 1× SHA3 check (fail-fast)| Fast linear polynomial check|

## Eirn-Ratchet: Continuous Epoch Bindings

Authenticating the initial handshake is insufficient for enduring persistent post-compromise security contexts. **Eirn-Ratchet** seamlessly ties the Eirn-KCP authentication layer continuously into the session lifecycle. 

By natively mapping the Hash or Lattice Zero-Knowledge proofs directly onto ratchet epoch shifts, the sender explicitly forces transient ephemerals to mathematically trace securely backwards to the root identity. This systematically defeats \textit{Key Compromise Impersonation (KCI)} and asymmetric session-hijacking threat vectors out of the box without requiring expensive continuous Ed25519 signature generations.

## Protocol Architecture & Flow

```text
Alice (Sender)                                Bob (Receiver)
─────────────────                             ──────────────────
1. (ek_A, esk_A) ← KeyGen()
2. ct1..ct3 ← Encapsulations
3. ct4 ← NAXOS.Encaps(spk_B, sk_A, esk_A)
-----------------------------
4a. Hash Mode: π ← Hash.Prove(sk_A, ctx)
4b. Lattice Mode: π ← LatticeZK.Prove(Lattice_sk, ctx)

               MSG0' = (pk_A, ek_A, ct1..ct4, π_KCP)
               ─────────────────────────────────────────────►

                                          1. Verify(pk_A, ctx, π_KCP) 
                                             (abort if invalid — fail-fast)
                                          2. K1..K4 ← Decaps(ct1..ct4)
                                          3. ss ← KDF(K1‖K2‖K3‖K4‖...)
```

## Project Structure

```text
eirn-zk/
├── eirn_kem/          # Simulated MLWE-KEM core
│   ├── kem.py         # KeyGen, Encaps, Decaps
│   └── params.py      # Core parameters (Eirn-512, Eirn-768)
├── naxos_kem/         # NAXOS-KEM (eCK-secure auth primitive)
├── lattice_zk/        # Lattice-Native ZK module
│   └── prover.py      # Lyubashevsky MLWE rejection sampling
├── zk/                # Hash-commitment module
├── ratchet/           # Eirn-Ratchet: Continuous Epoch Binding
├── protocol/          # Eirn-KCP orchestration logic
│   ├── handshake.py   # Dual-mode MSG0' construction & verification
│   └── session.py     # Session key derivation
├── tests/             # Pytest framework (55 Tests passing)
├── whitepaper/        # LaTeX research paper & mathematical boundaries
├── main.py            # Executable protocol simulation
├── pytest.ini         # Pytest rendering configuration
├── conftest.py        # Terminal formatting hooks
└── README.md          # Project documentation
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the complete protocol simulation
python3 main.py

# Execute the test suite
python3 -m pytest tests/
```

## Zero-Knowledge Mathematics (Lattice Mode)

To extract full formal boundaries natively from the MLWE relationship $\mathbf{t} = \mathbf{A}\mathbf{s} + \mathbf{e} \bmod q$:
* **Rejection Sampling**: The verifier constructs an interactive mathematical query $\mathbf{z} = \mathbf{y} + c\mathbf{s}$ mapped aggressively over bounded uniform geometrical intervals $[-\gamma_1, \gamma_1]$. The prover geometrically aborts internally to erase any biased algebraic drift.
* **Formal Extractor Yield**: If the interaction successfully produces identical challenge commitments, an active extractor theoretically manipulates $(c - c')^{-1} (\mathbf{z} - \mathbf{z}')$ to mathematically expose underlying identity keys cleanly without solving generic shortest vector thresholds globally.

## Limitations

- **Research prototype**: Not audited for active production pipelines structurally. 
- **Math Abstractions**: Evaluates generic python geometric simulations; operates unverified against modern constant-time side-channel metrics natively. 

## References
Please check the `/whitepaper` output for full formal constraints referencing standard properties by Lyubashevsky (2012), K-Waay models (2024), and original Fujisaki-Okamoto bounds.

## License
Eirn-KCP Dual-Mode Prototype. Distributed under standard academic research disclosures.
