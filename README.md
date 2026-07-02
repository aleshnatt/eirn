# Eirn-KCP

Eirn-KCP is a Rust crate for modeling an asynchronous key exchange flow with prekey bundles, transcript-bound session keys, and explicit key consistency checks.

[![Crates.io](https://img.shields.io/crates/v/eirn-kcp.svg)](https://crates.io/crates/eirn-kcp) [![docs.rs](https://docs.rs/eirn-kcp/badge.svg)](https://docs.rs/eirn-kcp) [![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

## What This Crate Does

This crate packages the core Eirn-KCP handshake surface as a Rust library. A receiver creates a private prekey bundle and publishes only the public half; a sender uses that public bundle to build a fixed-size initial message and derive a session key. The receiver verifies the message, consumes one one-time prekey, and derives the matching session key from its private state.

The protocol model combines a crate-specific hash-based encapsulation path, a NAXOS-style sender-bound encapsulation leg, and KCP-Lite key consistency proof. KCP-Lite is implemented with Ed25519 signatures over the session context plus an anchor hash; it is a consistency check, not a formal zero-knowledge proof system.

The library is intended for protocol experimentation, test vectors, and implementation review of the Eirn-KCP message flow. It gives reviewers concrete Rust APIs for key generation, prekey handling, message encoding, proof verification, and transcript-bound key derivation.

## Security Notice

Known limitations:
- KCP-Lite uses Ed25519 signatures and an anchor hash; it is not a formal zero-knowledge proof system.
- Strict lattice-native KCP mode is reserved but not implemented.

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

## Parameter Sets

| Name | Security Target | Key Fields |
| --- | --- | --- |
| Eirn-512 | targets an Eirn-512 profile, without audited security-bit guarantees | `n = 256`, `k = 2`, `q = 3329`, 32-byte keys, 64-byte ciphertexts |
| Eirn-768 | targets an Eirn-768 profile, without audited security-bit guarantees | `n = 256`, `k = 3`, `q = 3329`, 32-byte keys, 64-byte ciphertexts |

## Building and Testing

```bash
cargo build --release
cargo test --all-features
cargo test --doc
```

## License

MIT OR Apache-2.0.
