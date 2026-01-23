use std::io::{Error, ErrorKind, Write};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

#[derive(Debug, Clone)]
pub enum PacketError {
    Decode(String),
    Encode(String),
    Overflow(String),
    TooLarge(String),
    Utf8(String),
    ConnectionLost
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PacketError::Decode(e) => write!(f, "Decode error: {}", e),
            PacketError::Encode(e) => write!(f, "Encode error: {}", e),
            PacketError::Overflow(e) => write!(f, "Overflow error: {}", e),
            PacketError::TooLarge(e) => write!(f, "Size error: {}", e),
            PacketError::Utf8(e) => write!(f, "UTF-8 error: {}", e),
            PacketError::ConnectionLost => write!(f, "Connection lost"),
        }
    }
}

impl std::error::Error for PacketError {}

impl From<PacketError> for Error {
    fn from(e: PacketError) -> Self {
        Error::new(ErrorKind::InvalidData, e.to_string())
    }
}

impl<T: TryFromPrimitive> From<TryFromPrimitiveError<T>> for PacketError {
    fn from(err: TryFromPrimitiveError<T>) -> Self {
        PacketError::Decode(format!("Invalid primitive value: {:?}", err.number))
    }
}
