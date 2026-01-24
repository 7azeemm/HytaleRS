use std::error::Error;
use std::fmt::{Debug, Display};
use num_enum::TryFromPrimitiveError;

#[derive(Debug, Clone)]
pub enum PacketError {
    Error { reason: &'static str, error: String },
    
    DecodeEOF { field: &'static str },
    DecodeVarIntOverflow { field: &'static str },
    DecodeOutOfBounds { field: &'static str, offset: i32, available: usize },
    DecodeInvalidUtf8 { field: &'static str },
    DecodeInvalidPrimitiveValue { field: &'static str, value: u8 },
    DecodeNegativeOffset { field: &'static str, offset: i32 },
    DecodeInvalidPayloadLength { size: u32, min: usize, max: u32 },

    EncodePacketTooLarge { size: usize, max: usize },
    EncodeTooManyOffsets { count: usize, expected: usize },
    EncodeOverflow { field: &'static str },
    EncodeStringTooLong { field: &'static str, len: usize, max: usize },

    ConnectionLost,
}

impl PacketError {
    pub fn message(&self) -> String {
        match self {
            Self::Error { reason, error } => format!("{}: {}", reason, error),
            
            Self::DecodeEOF { field } => format!("EOF while reading '{}'", field),
            Self::DecodeVarIntOverflow { field } => format!("VarInt overflow in '{}'", field),
            Self::DecodeInvalidUtf8 { field } => format!("Invalid UTF-8 in field '{}'", field),
            Self::DecodeInvalidPrimitiveValue { field, value } => format!(
                "Invalid primitive value in '{}': got 0x{:02X}", field, value
            ),
            Self::DecodeOutOfBounds { field, offset, available } => format!(
                "Out of bounds reading '{}': offset {} but only {} bytes available",
                field, offset, available
            ),
            Self::DecodeNegativeOffset { field, offset } => format!(
                "Negative offset in '{}': offset {} is invalid (must be >= -1)",
                field, offset
            ),
            Self::DecodeInvalidPayloadLength { size, min, max } => format!(
                "Invalid payload length {} (min: {}, max: {})",
                size, min, max
            ),
            
            Self::EncodeOverflow { field } => format!("Encoding overflow in field '{}'", field),
            Self::EncodePacketTooLarge { size, max } => format!(
                "Packet too large: {} bytes exceeds max {} bytes", size, max
            ),
            Self::EncodeTooManyOffsets { count, expected } => format!(
                "Too many offsets recorded: {} but expected {}",
                count, expected
            ),
            Self::EncodeStringTooLong { field, len, max } => format!(
                "String in '{}' too long: {} bytes exceeds max {} bytes",
                field, len, max
            ),
            
            Self::ConnectionLost => "Connection lost".to_string(),
        }
    }
}

impl Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl Error for PacketError {}

impl<T: Debug + num_enum::TryFromPrimitive<Primitive = u8>> From<TryFromPrimitiveError<T>> for PacketError {
    fn from(err: TryFromPrimitiveError<T>) -> Self {
        PacketError::DecodeInvalidPrimitiveValue {
            field: "enum",
            value: err.number,
        }
    }
}