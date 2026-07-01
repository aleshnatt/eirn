use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EirnError {
    AuthenticationFailed,
    KeyMismatch,
    InvalidCiphertextLength { expected: usize, actual: usize },
    InvalidMessageLength { expected: usize, actual: usize },
    InvalidProofLength { expected: usize, actual: usize },
    InvalidKeyLength { expected: usize, actual: usize },
    NoOneTimePrekeys,
    StrictModeUnavailable,
}

impl fmt::Display for EirnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EirnError::AuthenticationFailed => f.write_str("authentication failed"),
            EirnError::KeyMismatch => {
                f.write_str("secret key does not match the supplied public key")
            }
            EirnError::InvalidCiphertextLength { expected, actual } => {
                write!(
                    f,
                    "invalid ciphertext length: expected {expected}, got {actual}"
                )
            }
            EirnError::InvalidMessageLength { expected, actual } => {
                write!(
                    f,
                    "invalid message length: expected {expected}, got {actual}"
                )
            }
            EirnError::InvalidProofLength { expected, actual } => {
                write!(f, "invalid proof length: expected {expected}, got {actual}")
            }
            EirnError::InvalidKeyLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected}, got {actual}")
            }
            EirnError::NoOneTimePrekeys => f.write_str("no one-time prekeys remaining"),
            EirnError::StrictModeUnavailable => {
                f.write_str("KCP strict lattice mode is not implemented in this crate version")
            }
        }
    }
}

impl std::error::Error for EirnError {}

pub type Result<T> = core::result::Result<T, EirnError>;
