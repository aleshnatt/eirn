//! # Eirn-KCP
//!
//! Eirn-KCP models an asynchronous prekey key exchange with ML-KEM sender
//! messages, transcript-bound session keys, ML-DSA key consistency checks, and
//! an optional lattice-native zero-knowledge KCP-Strict mode. The default
//! profile is ML-KEM-768 plus ML-DSA-65; `PARAMS_1024` enables the ML-KEM-1024
//! plus ML-DSA-87 profile through the `*_with_params` APIs.
//!
//! # Quick Start
//!
//! ```rust
//! use eirn_kcp::{generate_prekey_bundle, keygen, receiver_handshake, sender_handshake};
//!
//! let (alice_pk, alice_sk) = keygen();
//! let mut bob_bundle = generate_prekey_bundle(10);
//! let bob_public = bob_bundle.public_bundle();
//! let (msg0, alice_key) = sender_handshake(&alice_sk, &alice_pk, &bob_public)?;
//! let bob_key = receiver_handshake(&mut bob_bundle, &msg0)?;
//! assert_eq!(alice_key, bob_key);
//! # Ok::<(), eirn_kcp::EirnError>(())
//! ```
//!
//! # Architecture
//!
//! The `kem` module owns ML-KEM key generation, encapsulation, decapsulation,
//! and fixed-size key material. The `prekey`, `handshake`, and `naxos` modules
//! build the asynchronous sender/receiver flow from identity keys, signed
//! prekeys, one-time prekeys, and sender-bound encapsulation. The `zk` module
//! contains both the ML-DSA-backed KCP-Lite proof and the lattice-native
//! KCP-Strict proof relation, while `session` and `util` provide
//! transcript-bound key derivation and hash primitives.

pub mod error;
pub mod handshake;
pub mod kem;
mod lattice_zk;
pub mod naxos;
pub mod params;
pub mod prekey;
pub mod session;
pub mod util;
pub mod zk;

pub use error::{EirnError, Result};
pub use handshake::{
    build_context, receiver_handshake, sender_handshake, sender_handshake_strict, Msg0Prime,
};
pub use kem::{
    decaps, encaps, encaps_deterministic, keygen, keygen_from_seed, keygen_with_params, Ciphertext,
    PublicKey, SecretKey,
};
pub use params::{EirnParams, PARAMS_1024, PARAMS_768};
pub use prekey::{
    generate_prekey_bundle, generate_prekey_bundle_with_params, PrekeyBundle, PublicPrekeyBundle,
};
pub use session::{derive_message_key, derive_session_key};
pub use zk::{
    kcp_lite_prove, kcp_lite_prove_for_key, kcp_lite_verify, kcp_strict_prove, kcp_strict_verify,
    KcpLiteProof, KcpMode, KcpStrictProof,
};
