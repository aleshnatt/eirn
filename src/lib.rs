//! # Eirn-KCP
//!
//! Eirn-KCP models an asynchronous prekey key exchange with fixed-size sender
//! messages, transcript-bound session keys, and explicit key consistency checks.
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
//! The `kem` module owns key generation, encapsulation, decapsulation, and
//! fixed-size key material. The `prekey`, `handshake`, and `naxos` modules build
//! the asynchronous sender/receiver flow from identity keys, signed prekeys,
//! one-time prekeys, and sender-bound encapsulation. The `zk` module contains
//! the KCP-Lite consistency proof used by the current handshake, while `session`
//! and `util` provide transcript-bound key derivation and hash primitives.

pub mod error;
pub mod handshake;
pub mod kem;
pub mod naxos;
pub mod params;
pub mod prekey;
pub mod session;
pub mod util;
pub mod zk;

pub use error::{EirnError, Result};
pub use handshake::{build_context, receiver_handshake, sender_handshake, Msg0Prime};
pub use kem::{decaps, encaps, encaps_deterministic, keygen, Ciphertext, PublicKey, SecretKey};
pub use params::{EirnParams, PARAMS_512, PARAMS_768};
pub use prekey::{generate_prekey_bundle, PrekeyBundle, PublicPrekeyBundle};
pub use session::{derive_message_key, derive_session_key};
pub use zk::{kcp_lite_prove, kcp_lite_prove_for_key, kcp_lite_verify, KcpLiteProof, KcpMode};
