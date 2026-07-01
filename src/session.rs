use crate::util::kdf;

const SESSION_LABEL: &str = "Eirn-ZK-v1";
const MESSAGE_LABEL: &str = "Eirn-ZK-msg";

pub fn derive_session_key(
    shared_secrets: &[[u8; 32]],
    pk_a: &[u8],
    pk_b: &[u8],
    ek_a: &[u8],
    ciphertexts: &[&[u8]],
    additional_data: Option<&[u8]>,
) -> [u8; 32] {
    let mut inputs: Vec<&[u8]> = Vec::with_capacity(shared_secrets.len() + ciphertexts.len() + 4);
    inputs.extend(shared_secrets.iter().map(|s| s.as_slice()));
    inputs.extend([pk_a, pk_b, ek_a]);
    inputs.extend(ciphertexts.iter().copied());
    if let Some(data) = additional_data {
        if !data.is_empty() {
            inputs.push(data);
        }
    }
    kdf(&inputs, SESSION_LABEL, 32)
        .try_into()
        .expect("KDF output length is fixed")
}

pub fn derive_message_key(session_key: &[u8; 32], counter: u64) -> [u8; 32] {
    let counter = counter.to_be_bytes();
    kdf(&[session_key.as_slice(), &counter], MESSAGE_LABEL, 32)
        .try_into()
        .expect("KDF output length is fixed")
}
