#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EirnParams {
    pub name: &'static str,
    pub n: usize,
    pub k: usize,
    pub q: u32,
    pub eta1: u32,
    pub eta2: u32,
    pub sk_bytes: usize,
    pub pk_bytes: usize,
    pub ct_bytes: usize,
    pub ss_bytes: usize,
    pub coins_bytes: usize,
    pub nist_level: u8,
}

pub const PARAMS_512: EirnParams = EirnParams {
    name: "Eirn-512",
    n: 256,
    k: 2,
    q: 3329,
    eta1: 3,
    eta2: 2,
    sk_bytes: 32,
    pk_bytes: 32,
    ct_bytes: 64,
    ss_bytes: 32,
    coins_bytes: 32,
    nist_level: 1,
};

pub const PARAMS_768: EirnParams = EirnParams {
    name: "Eirn-768",
    n: 256,
    k: 3,
    q: 3329,
    eta1: 2,
    eta2: 2,
    sk_bytes: 32,
    pk_bytes: 32,
    ct_bytes: 64,
    ss_bytes: 32,
    coins_bytes: 32,
    nist_level: 3,
};
