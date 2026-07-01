use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Sha3_512, Shake256,
};

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data).into()
}

pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

pub fn kdf(inputs: &[&[u8]], label: &str, out_len: usize) -> Vec<u8> {
    let label = label.as_bytes();
    let mut buf =
        Vec::with_capacity(4 + label.len() + inputs.iter().map(|i| i.len() + 4).sum::<usize>());
    buf.extend_from_slice(&(label.len() as u16).to_be_bytes());
    buf.extend_from_slice(label);
    buf.extend_from_slice(&(inputs.len() as u16).to_be_bytes());
    for input in inputs {
        buf.extend_from_slice(&(input.len() as u32).to_be_bytes());
        buf.extend_from_slice(input);
    }
    shake256(&buf, out_len)
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
