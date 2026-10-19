use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CryptoError {
    #[error("Authentication failed: invalid proof hash (M1/M2)")]
    AuthenticationFailed,

    #[error("Invalid public key or weak ephemeral curve point detected")]
    InvalidEphemeralKey,

    #[error("Invalid salt length: expected 16 or 32 bytes, got {0}")]
    InvalidSaltLength(usize),

    #[error("Invalid buffer length for cryptographic operation: required {required}, available {available}")]
    InvalidBufferLength { required: usize, available: usize },

    #[error("Cryptographic RNG failure")]
    RngError,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
}

