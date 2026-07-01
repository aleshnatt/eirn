//! Eirn-KCP protocol components.
//!
//! This crate contains a Rust port of the original Eirn-KCP prototype:
//! a hash-based KEM simulation, KCP-Lite key consistency proofs, NAXOS
//! encapsulation coins, prekey bundles, transcript-bound session KDFs, and
//! initial handshake helpers.
//!
//! The KEM and KCP-Lite proof are protocol-model implementations intended for
//! integration testing, experimentation, and API development. They are not a
//! replacement for audited production post-quantum primitives.

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
pub use kem::{
    decaps, encaps, encaps_deterministic, keygen, Ciphertext, PublicKey, SecretKey,
    KEY_DERIVE_PREFIX,
};
pub use params::{EirnParams, PARAMS_512, PARAMS_768};
pub use prekey::{generate_prekey_bundle, PrekeyBundle};
pub use session::{derive_message_key, derive_session_key};
pub use zk::{kcp_lite_prove, kcp_lite_prove_for_key, kcp_lite_verify, KcpLiteProof, KcpMode};
