use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ProtoError {
    #[error("Buffer too small: required {required} bytes, available {available} bytes")]
    BufferTooSmall { required: usize, available: usize },

    #[error("Invalid EoIP flags/version: expected 0x2001, got 0x{0:04x}")]
    InvalidEoipFlags(u16),

    #[error("Invalid EoIP protocol type: expected 0x6400, got 0x{0:04x}")]
    InvalidEoipProtocol(u16),

    #[error("EoIP frame length mismatch: header declares {declared} bytes, but payload has {actual} bytes")]
    EoipLengthMismatch { declared: usize, actual: usize },

    #[error("Invalid MAC address format: {0}")]
    InvalidMacAddress(String),

    #[error("Unknown MAC-Telnet packet type: 0x{0:02x}")]
    UnknownPacketType(u8),

    #[error("Invalid MAC-Telnet magic/version: expected 1, got {0}")]
    InvalidMacTelnetVersion(u8),

    #[error("Invalid MNDP TLV format or truncated data")]
    InvalidMndpTlv,

    #[error("Payload exceeds maximum allowable MTU ({0} bytes)")]
    PayloadExceedsMtu(usize),
}
