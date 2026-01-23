use std::io::{Cursor, Error, ErrorKind, Read, Write};
use quinn::RecvStream;
use super::packet::*;

const MAX_PACKET_SIZE: usize = 262_144; // 256 KB
const MAX_STRING_LENGTH: usize = 32_768; // 32 KB
const MAX_VARINT_BYTES: usize = 5; // Max bytes for i32 varint

#[derive(Debug, Clone)]
pub enum CodecError {
    Decode(String),
    Encode(String),
    Overflow(String),
    TooLarge(String),
    Utf8(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CodecError::Decode(e) => write!(f, "Decode error: {}", e),
            CodecError::Encode(e) => write!(f, "Encode error: {}", e),
            CodecError::Overflow(e) => write!(f, "Overflow error: {}", e),
            CodecError::TooLarge(e) => write!(f, "Size error: {}", e),
            CodecError::Utf8(e) => write!(f, "UTF-8 error: {}", e),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<CodecError> for Error {
    fn from(e: CodecError) -> Self {
        Error::new(ErrorKind::InvalidData, e.to_string())
    }
}

pub struct PacketCodec;

impl PacketCodec {
    /// Frame format: [payload_len: u32 LE][packet_id: u32 LE][body...]
    /// payload_len = len(body) only, NOT including packet_id
    pub fn encode(packet: &impl Packet) -> Result<Vec<u8>, CodecError> {
        let mut body_buf = Vec::with_capacity(512);

        // Encode packet body
        packet.encode(&mut body_buf)
            .map_err(|e| CodecError::Encode(format!("Failed to encode packet: {}", e)))?;

        let packet_id = packet.packet_id();
        let payload_len = body_buf.len();

        // Validate size
        if payload_len > MAX_PACKET_SIZE {
            return Err(CodecError::TooLarge(format!(
                "Packet payload {} exceeds max size {}",
                payload_len, MAX_PACKET_SIZE
            )));
        }

        // Build frame: [payload_len: u32 LE][packet_id: u32 LE][body]
        let mut out = Vec::with_capacity(8 + payload_len);
        out.extend_from_slice(&(payload_len as u32).to_le_bytes());
        out.extend_from_slice(&packet_id.to_le_bytes());
        out.extend_from_slice(&body_buf);

        Ok(out)
    }

    /// Read framed packet from stream
    /// Returns: (packet_id, body_bytes)
    pub async fn read_framed_packet(recv: &mut RecvStream) -> Result<(u32, Vec<u8>), CodecError> {
        // Read header: [payload_len: u32 LE][packet_id: u32 LE]
        let mut header = [0u8; 8];
        recv.read_exact(&mut header).await
            .map_err(|e| CodecError::Decode(format!("Failed to read packet header: {}", e)))?;

        let payload_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let packet_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

        // Validate payload length
        if payload_len == 0 {
            return Err(CodecError::Decode("Empty packet payload".into()));
        }
        if payload_len > MAX_PACKET_SIZE {
            return Err(CodecError::TooLarge(format!(
                "Packet payload {} exceeds max size {}",
                payload_len, MAX_PACKET_SIZE
            )));
        }

        // Read payload (body only, packet_id already extracted)
        let mut payload = vec![0u8; payload_len];
        recv.read_exact(&mut payload).await
            .map_err(|e| CodecError::Decode(format!("Failed to read packet payload: {}", e)))?;

        Ok((packet_id, payload))
    }

    /// Decode packet from raw bytes [packet_id: u32 LE][body...]
    pub fn decode<P: Packet>(data: &[u8]) -> Result<P, CodecError> {
        if data.len() < 4 {
            return Err(CodecError::Decode("Packet too short to contain ID".into()));
        }

        let _packet_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let body = &data[4..];

        let mut cursor = Cursor::new(body);
        // P::decode(&mut cursor)
        Err(CodecError::Decode("e".to_owned()))
    }
}

pub trait PacketField: Sized {
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()>;
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError>;
}

impl PacketField for u8 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&[*self])
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)
            .map_err(|e| CodecError::Decode(format!("Failed to read u8: {}", e)))?;
        Ok(byte[0])
    }
}

impl PacketField for u16 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 2];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read u16: {}", e)))?;
        Ok(u16::from_le_bytes(bytes))
    }
}

impl PacketField for u32 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read u32: {}", e)))?;
        Ok(u32::from_le_bytes(bytes))
    }
}

impl PacketField for u64 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 8];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read u64: {}", e)))?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl PacketField for u128 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 16];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read u128: {}", e)))?;
        Ok(u128::from_le_bytes(bytes))
    }
}

impl PacketField for i8 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&[*self as u8])
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)
            .map_err(|e| CodecError::Decode(format!("Failed to read i8: {}", e)))?;
        Ok(byte[0] as i8)
    }
}

impl PacketField for i16 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 2];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read i16: {}", e)))?;
        Ok(i16::from_le_bytes(bytes))
    }
}


impl PacketField for i32 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read i32: {}", e)))?;
        Ok(i32::from_le_bytes(bytes))
    }
}

impl PacketField for i64 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 8];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read i64: {}", e)))?;
        Ok(i64::from_le_bytes(bytes))
    }
}

impl PacketField for i128 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 16];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read i128: {}", e)))?;
        Ok(i128::from_le_bytes(bytes))
    }
}

impl PacketField for f32 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read f32: {}", e)))?;
        Ok(f32::from_le_bytes(bytes))
    }
}

impl PacketField for f64 {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&self.to_le_bytes())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut bytes = [0u8; 8];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read f64: {}", e)))?;
        Ok(f64::from_le_bytes(bytes))
    }
}

impl PacketField for bool {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&[*self as u8])
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)
            .map_err(|e| CodecError::Decode(format!("Failed to read bool: {}", e)))?;
        Ok(byte[0] != 0)
    }
}

impl PacketField for String {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        let bytes = self.as_bytes();
        writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
        writer.write_all(bytes)?;
        Ok(())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)
            .map_err(|e| CodecError::Decode(format!("Failed to read string length: {}", e)))?;

        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_STRING_LENGTH {
            return Err(CodecError::TooLarge(format!(
                "String too long: {} bytes (max: {})",
                len, MAX_STRING_LENGTH
            )));
        }

        let mut bytes = vec![0u8; len];
        reader.read_exact(&mut bytes)
            .map_err(|e| CodecError::Decode(format!("Failed to read string data: {}", e)))?;

        String::from_utf8(bytes)
            .map_err(|e| CodecError::Utf8(format!("Invalid UTF-8 in string: {}", e)))
    }
}

impl<T: PacketField> PacketField for Vec<T> {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        writer.write_all(&(self.len() as u32).to_le_bytes())?;
        for item in self {
            item.encode(writer)?;
        }
        Ok(())
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)
            .map_err(|e| CodecError::Decode(format!("Failed to read Vec length: {}", e)))?;

        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_PACKET_SIZE {
            return Err(CodecError::TooLarge(format!(
                "Array too long: {} items", len
            )));
        }

        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            items.push(T::decode(reader)?);
        }
        Ok(items)
    }
}

impl<T: PacketField> PacketField for Option<T> {
    #[inline]
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        match self {
            Some(val) => {
                writer.write_all(&[1u8])?;
                val.encode(writer)
            }
            None => writer.write_all(&[0u8]),
        }
    }

    #[inline]
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError> {
        let mut present = [0u8; 1];
        reader.read_exact(&mut present)
            .map_err(|e| CodecError::Decode(format!("Failed to read Option flag: {}", e)))?;

        if present[0] != 0 {
            Ok(Some(T::decode(reader)?))
        } else {
            Ok(None)
        }
    }
}
