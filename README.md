# Eirn-KCP

Eirn-KCP is a Rust crate for modeling a post-quantum asynchronous key exchange flow with prekey bundles, transcript-bound session keys, ML-KEM encapsulation, ML-DSA key consistency checks, and an optional lattice-native zero-knowledge KCP-Strict mode.

[![Crates.io](https://img.shields.io/crates/v/eirn-kcp.svg)](https://crates.io/crates/eirn-kcp) [![docs.rs](https://docs.rs/eirn-kcp/badge.svg)](https://docs.rs/eirn-kcp) [![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

## What This Crate Does

This crate packages the core Eirn-KCP handshake surface as a Rust library. A receiver creates a private prekey bundle and publishes only the public half; a sender uses that public bundle to build a fixed-size initial message and derive a session key. The receiver verifies the message, consumes one one-time prekey, and derives the matching session key from its private state.

The protocol model combines FIPS 203 ML-KEM encapsulation, a sender-bound transcript KDF leg, and two key-consistency modes. KCP-Lite is implemented with FIPS 204 ML-DSA signatures over the session context plus an anchor hash. KCP-Strict adds a lattice-native Fiat-Shamir proof for the formal relation `t = A*s mod q`, proving knowledge of a short witness bound to the sender public key and transcript.

The library is intended for protocol experimentation, test vectors, and implementation review of the Eirn-KCP message flow. It gives reviewers concrete Rust APIs for key generation, prekey handling, message encoding, proof verification, and transcript-bound key derivation.

## Security Notice

Known limitations:
- KCP-Lite is the ML-DSA signature-backed fast path.
- KCP-Strict is the lattice-native zero-knowledge key-consistency path.
- The default profile is ML-KEM-768 plus ML-DSA-65. The higher-strength ML-KEM-1024 / ML-DSA-87 profile is available through the `*_with_params` APIs.

## Quick Start

```rust
use eirn_kcp::{generate_prekey_bundle, keygen, receiver_handshake, sender_handshake};

fn main() -> Result<(), eirn_kcp::EirnError> {
    let (alice_pk, alice_sk) = keygen();
    let mut bob_bundle = generate_prekey_bundle(10);
    let bob_public = bob_bundle.public_bundle();

    let (msg0, alice_key) = sender_handshake(&alice_sk, &alice_pk, &bob_public)?;
    let bob_key = receiver_handshake(&mut bob_bundle, &msg0)?;

    assert_eq!(alice_key, bob_key);
    Ok(())
}
```

For the formal lattice-native proof path, use `sender_handshake_strict`:

```rust
use eirn_kcp::{generate_prekey_bundle, keygen, receiver_handshake, sender_handshake_strict};

fn main() -> Result<(), eirn_kcp::EirnError> {
    let (alice_pk, alice_sk) = keygen();
    let mut bob_bundle = generate_prekey_bundle(10);
    let bob_public = bob_bundle.public_bundle();

    let (msg0, alice_key) = sender_handshake_strict(&alice_sk, &alice_pk, &bob_public)?;
    let bob_key = receiver_handshake(&mut bob_bundle, &msg0)?;

    assert_eq!(alice_key, bob_key);
    Ok(())
}
```

## Parameter Sets

| Name | Security Target | Key Fields |
| --- | --- | --- |
| Eirn-ML-KEM-768-ML-DSA-65 | default implemented profile, NIST security category 3 primitives | ML-KEM public key 1184 bytes, ML-DSA verifying key 1952 bytes, lattice statement 64 bytes, ML-KEM ciphertext 1088 bytes, ML-DSA signature 3309 bytes |
| Eirn-ML-KEM-1024-ML-DSA-87 | implemented category 5 profile via `PARAMS_1024` | ML-KEM public key 1568 bytes, ML-DSA verifying key 2592 bytes, lattice statement 64 bytes, ML-KEM ciphertext 1568 bytes, ML-DSA signature 4627 bytes |

## Building and Testing

```bash
cargo build --release
cargo test --all-features
cargo test --doc
```

## License

MIT OR Apache-2.0.
