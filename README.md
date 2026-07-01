# Eirn-KCP

Rust implementation of Eirn-KCP protocol components:

- Eirn KEM simulation with FO-style implicit rejection
- KCP-Lite key consistency proof
- NAXOS-derived encapsulation coins
- Prekey bundle generation and one-time prekey consumption
- Transcript-bound session and message KDFs
- MSG0' sender and receiver handshake helpers

This crate is the canonical Rust library implementation for the current
prototype.

## Install

```toml
[dependencies]
eirn-kcp = "0.1"
```

## Example

```rust
use eirn_kcp::{generate_prekey_bundle, keygen, receiver_handshake, sender_handshake};

let (alice_pk, alice_sk) = keygen();
let mut bob_bundle = generate_prekey_bundle(10);

let (msg0, alice_session_key) = sender_handshake(&alice_sk, &alice_pk, &bob_bundle)?;
let bob_session_key = receiver_handshake(&mut bob_bundle, &msg0)?;

assert_eq!(alice_session_key, bob_session_key);
# Ok::<(), eirn_kcp::EirnError>(())
```

## Security Status

This crate is suitable for protocol experimentation and integration tests. The
KEM is a hash-based simulation that preserves the intended interface, not an
audited MLWE KEM. KCP-Lite provides context-bound wrong-key detection for the
prototype threat model; strict lattice ZKPoK mode is not implemented in this
release and returns an explicit error instead of panicking.

Do not use this crate as a production cryptographic primitive without replacing
the simulated KEM and proof layer with audited implementations.

## Development

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo package --allow-dirty --list
```

## License

MIT
