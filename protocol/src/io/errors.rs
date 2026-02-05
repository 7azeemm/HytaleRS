use std::error::Error;
use std::fmt::{Debug, Display};
use std::string::FromUtf8Error;
use num_enum::TryFromPrimitiveError;

#[derive(Debug, Clone)]
pub enum PacketError {
    Error(String),
    DecodeError(String),
    EncodeError(String),
}

impl PacketError {
    pub fn message(&self) -> String {
        match self {
            Self::Error(err) => err.to_owned(),
            Self::DecodeError(err) => format!("Decode Error: {}", err),
            Self::EncodeError(err) => format!("Encode Error: {}", err),
        }
    }
}

impl Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl Error for PacketError {}

impl From<std::io::Error> for PacketError {
    fn from(err: std::io::Error) -> Self {
        PacketError::Error(err.to_string())
    }
}

impl<T: Debug + num_enum::TryFromPrimitive<Primitive = u8>> From<TryFromPrimitiveError<T>> for PacketError {
    fn from(err: TryFromPrimitiveError<T>) -> Self {
        PacketError::DecodeError(format!("Invalid enum value: {:?}", err))
    }
}

impl From<String> for PacketError {
    fn from(value: String) -> Self {
        PacketError::Error(value)
    }
}

impl From<FromUtf8Error> for PacketError {
    fn from(_: FromUtf8Error) -> Self {
        PacketError::DecodeError("Invalid UTF-8 string".to_owned())
    }
}

pub type PacketResult<T> = Result<T, PacketError>;