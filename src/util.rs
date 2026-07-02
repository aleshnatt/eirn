//! Hashing, XOF, KDF, and byte comparison helpers.
//!
//! These helpers centralize primitive use for the crate. They resist accidental
//! ambiguity in KDF inputs through explicit length prefixes and use `subtle` for
//! equality checks where the caller expects constant-time byte comparison. They
//! do not erase input buffers or make higher-level protocol choices secure by
//! themselves.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Sha3_512, Shake256,
};

/// Hashes `data` with SHA3-256.
///
/// # Security
///
/// Domain separation must be supplied by the caller in `data`. Reusing this
/// helper with ambiguous concatenations can bind the wrong transcript.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

/// Hashes `data` with SHA3-512.
///
/// # Security
///
/// Domain separation must be supplied by the caller in `data`. This helper is
/// not currently used by the public protocol path.
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data).into()
}

/// Expands `data` with SHAKE256 to `out_len` bytes.
///
/// # Security
///
/// Domain separation must be supplied by the caller in `data`. Very large
/// `out_len` values allocate memory proportional to the requested output.
pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

/// Derives variable-length output from labeled, length-prefixed inputs.
///
/// # Security
///
/// The `label` must be unique for the derived key purpose. Input order is part
/// of the derived value, so both protocol participants must pass fields in the
/// same order.
pub fn kdf(inputs: &[&[u8]], label: &str, out_len: usize) -> Vec<u8> {
    let label = label.as_bytes();
    let mut encoded_inputs =
        Vec::with_capacity(4 + label.len() + inputs.iter().map(|i| i.len() + 4).sum::<usize>());
    encoded_inputs.extend_from_slice(&(label.len() as u16).to_be_bytes());
    encoded_inputs.extend_from_slice(label);
    encoded_inputs.extend_from_slice(&(inputs.len() as u16).to_be_bytes());
    for input in inputs {
        encoded_inputs.extend_from_slice(&(input.len() as u32).to_be_bytes());
        encoded_inputs.extend_from_slice(input);
    }
    shake256(&encoded_inputs, out_len)
}

/// Compares two byte slices using `subtle` constant-time equality.
///
/// # Security
///
/// This helper avoids early-exit comparison for equal-length slices. Length
/// differences are still public through the slice lengths supplied by callers.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
