//! Parameter metadata for Eirn-KCP protocol profiles.
//!
//! The default profile uses FIPS-standard post-quantum primitives:
//! ML-KEM-768 for encapsulation, ML-DSA-65 for KCP-Lite signatures, and a
//! lattice statement for KCP-Strict. The fields are the concrete wire sizes used
//! by the crate APIs.

/// Public parameter metadata attached to keys and ciphertexts.
///
/// The type records the protocol profile and fixed byte sizes expected by the
/// Eirn-KCP APIs. Matching parameters prevent accidental cross-profile use of
/// keys and ciphertexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EirnParams {
    pub name: &'static str,
    pub n: usize,
    pub k: usize,
    pub q: u32,
    pub eta1: u32,
    pub eta2: u32,
    pub sk_bytes: usize,
    pub kem_pk_bytes: usize,
    pub sig_pk_bytes: usize,
    pub zk_statement_bytes: usize,
    pub pk_bytes: usize,
    pub ct_bytes: usize,
    pub ss_bytes: usize,
    pub coins_bytes: usize,
    pub sig_bytes: usize,
    pub proof_bytes: usize,
    pub strict_proof_bytes: usize,
    pub nist_level: u8,
}

/// Default Eirn-KCP profile: ML-KEM-768 plus ML-DSA-65.
pub const PARAMS_768: EirnParams = EirnParams {
    name: "Eirn-ML-KEM-768-ML-DSA-65",
    n: 256,
    k: 3,
    q: 3329,
    eta1: 2,
    eta2: 2,
    sk_bytes: 96,
    kem_pk_bytes: 1184,
    sig_pk_bytes: 1952,
    zk_statement_bytes: 64,
    pk_bytes: 3200,
    ct_bytes: 1088,
    ss_bytes: 32,
    coins_bytes: 32,
    sig_bytes: 3309,
    proof_bytes: 3373,
    strict_proof_bytes: 224,
    nist_level: 3,
};

/// Higher-strength Eirn-KCP profile: ML-KEM-1024 plus ML-DSA-87.
pub const PARAMS_1024: EirnParams = EirnParams {
    name: "Eirn-ML-KEM-1024-ML-DSA-87",
    n: 256,
    k: 4,
    q: 3329,
    eta1: 2,
    eta2: 2,
    sk_bytes: 96,
    kem_pk_bytes: 1568,
    sig_pk_bytes: 2592,
    zk_statement_bytes: 64,
    pk_bytes: 4224,
    ct_bytes: 1568,
    ss_bytes: 32,
    coins_bytes: 32,
    sig_bytes: 4627,
    proof_bytes: 4691,
    strict_proof_bytes: 224,
    nist_level: 5,
};
