//! # Eirn-KCP v2.0: Lattice-Native ZKPoK + KEM-Ratchet
//!
//! Production-ready scaffolding for the upgraded Key Consistency Proof layer.
//! This crate provides:
//!
//! - **params**: Dilithium-adapted parameter constants for Eirn-ZKP-512/768
//! - **poly**: Polynomial types and NTT stubs over R_q = Z_q[X]/(X^256 + 1)
//! - **zkp**: Prove/Verify function signatures for the Lyubashevsky Σ-protocol
//! - **ratchet**: KEM-ratchet state and message structures
//! - **msg**: Updated MSG₀' and cipher suite negotiation
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                   Application                    │
//! ├──────────────┬──────────────────┬────────────────┤
//! │   msg.rs     │   ratchet.rs     │   (handshake)  │
//! ├──────────────┴──────────────────┴────────────────┤
//! │                   zkp.rs                         │
//! │   lattice_prove() / lattice_verify()             │
//! │   kcp_lite_prove() / kcp_lite_verify()           │
//! ├──────────────────────────────────────────────────┤
//! │            poly.rs  +  params.rs                 │
//! │   NTT polynomial arithmetic over R_q             │
//! └──────────────────────────────────────────────────┘
//! ```

pub mod params;
pub mod poly;
pub mod zkp;
pub mod ratchet;
pub mod msg;

pub use params::*;
pub use zkp::{KcpMode, LatticeZkProof, lattice_prove, lattice_verify};
pub use msg::Msg0Prime;
