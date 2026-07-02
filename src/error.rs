use core::fmt;

/// Errors returned by Eirn-KCP protocol helpers.
///
/// Each variant represents a structural or authentication failure that prevents
/// the caller from accepting a message, proof, or key relationship. Errors do
/// not carry secret key material. Callers must treat authentication and
/// mismatch errors as terminal for the current handshake transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EirnError {
    /// A public proof or transcript authentication check failed.
    AuthenticationFailed,
    /// A secret key was used with a public key that it does not own.
    KeyMismatch,
    /// A ciphertext byte slice did not match the fixed wire size.
    InvalidCiphertextLength { expected: usize, actual: usize },
    /// A serialized `MSG0'` byte slice did not match the fixed wire size.
    InvalidMessageLength { expected: usize, actual: usize },
    /// A serialized KCP-Lite proof did not match the fixed wire size.
    InvalidProofLength { expected: usize, actual: usize },
    /// A serialized public key byte slice did not match the fixed wire size.
    InvalidKeyLength { expected: usize, actual: usize },
    /// Receiver state had no one-time prekey left to consume.
    NoOneTimePrekeys,
    /// The caller requested a reserved strict KCP mode.
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

/// Crate-local result type for Eirn-KCP operations.
///
/// The alias keeps public APIs tied to [`EirnError`] so callers can distinguish
/// malformed input, key mismatches, depleted prekey state, and unsupported
/// protocol modes. It carries no additional security property by itself.
/// Callers must still reject failed handshakes and proofs.
pub type Result<T> = core::result::Result<T, EirnError>;
