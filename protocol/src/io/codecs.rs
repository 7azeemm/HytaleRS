use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use uuid::Uuid;
use crate::io::decoder::Decoder;
use crate::io::encoder::Encoder;
use crate::io::errors::{PacketError, PacketResult};

const MAX_STRING_LENGTH: usize = 4_096_000;

pub trait PacketCodec: Sized {
    const SIZE: Option<usize>;
    const IS_OPTIONAL: bool = false;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()>;
    fn decode(dec: &mut Decoder) -> PacketResult<Self>;
    fn has_value(&self) -> bool { true }
}

impl PacketCodec for u8 {
    const SIZE: Option<usize> = Some(1);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&[*self]);
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(1)?;
        Ok(bytes[0])
    }
}

impl PacketCodec for u16 {
    const SIZE: Option<usize> = Some(2);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&self.to_le_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
}

impl PacketCodec for u32 {
    const SIZE: Option<usize> = Some(4);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&self.to_le_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

impl PacketCodec for u64 {
    const SIZE: Option<usize> = Some(8);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&self.to_le_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

impl PacketCodec for i8 {
    const SIZE: Option<usize> = Some(1);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&[*self as u8]);
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(1)?;
        Ok(bytes[0] as i8)
    }
}

impl PacketCodec for i16 {
    const SIZE: Option<usize> = Some(2);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&self.to_le_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(2)?;
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
    }
}

impl PacketCodec for i32 {
    const SIZE: Option<usize> = Some(4);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&self.to_le_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

impl PacketCodec for i64 {
    const SIZE: Option<usize> = Some(8);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&self.to_le_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

impl PacketCodec for bool {
    const SIZE: Option<usize> = Some(1);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let byte = if *self { 1u8 } else { 0u8 };
        enc.write_bytes(&[byte]);
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(1)?;
        match bytes[0] {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(PacketError::DecodeError(format!("Invalid boolean value: {}", v))),
        }
    }
}

impl PacketCodec for f32 {
    const SIZE: Option<usize> = Some(4);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&self.to_le_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(4)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

impl PacketCodec for f64 {
    const SIZE: Option<usize> = Some(8);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&self.to_le_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(8)?;
        Ok(f64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

impl PacketCodec for Uuid {
    const SIZE: Option<usize> = Some(16);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(self.as_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(16)?;
        Ok(Uuid::from_bytes(bytes.try_into().unwrap()))
    }
}

impl PacketCodec for String {
    const SIZE: Option<usize> = None;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let len = self.len();
        if len > MAX_STRING_LENGTH {
            return Err(PacketError::EncodeError(
                format!("String length {} exceeds maximum of {} while encoding", len, MAX_STRING_LENGTH)
            ));
        }

        enc.write_varint(len)?;
        enc.write_bytes(self.as_bytes());
        Ok(())
    }

    fn decode(decoder: &mut Decoder) -> PacketResult<Self> {
        let len = decoder.read_varint()?;
        if len < 0 {
            return Err(PacketError::DecodeError(
                format!("String length {} is negative while decoding", len)
            ));
        }

        if len > MAX_STRING_LENGTH {
            return Err(PacketError::DecodeError(
                format!("String length {} exceeds maximum of {} while decoding", len, MAX_STRING_LENGTH)
            ));
        }

        let bytes = decoder.read_bytes(len)?;
        Ok(String::from_utf8(bytes.to_vec())?)
    }
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct VarString<const MAX: usize>(pub String);

impl<const MAX: usize> PacketCodec for VarString<MAX> {
    const SIZE: Option<usize> = None;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let len = self.0.len();
        if len > MAX {
            return Err(PacketError::EncodeError(
                format!("VarString length {} exceeds maximum of {} while encoding", len, MAX)
            ));
        }

        enc.write_varint(len)?;
        enc.write_bytes(self.0.as_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let len = dec.read_varint()?;
        if len < 0 {
            return Err(PacketError::DecodeError(
                format!("VarString length {} is negative while decoding", len)
            ));
        }

        if len > MAX {
            return Err(PacketError::DecodeError(
                format!("VarString length {} exceeds maximum of {} while decoding", len, MAX)
            ));
        }

        let bytes = dec.read_bytes(len)?;
        Ok(Self(String::from_utf8(bytes.to_vec())?))
    }
}

impl<const MAX: usize> Deref for VarString<MAX> {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const MAX: usize> DerefMut for VarString<MAX> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const MAX: usize> From<String> for VarString<MAX> {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl<const MAX: usize> From<VarString<MAX>> for String {
    fn from(s: VarString<MAX>) -> Self {
        s.0
    }
}

impl<const MAX: usize> AsRef<str> for VarString<MAX> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> fmt::Display for VarString<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct FixedAsciiString<const N: usize>(pub String);

impl<const N: usize> PacketCodec for FixedAsciiString<N> {
    const SIZE: Option<usize> = Some(N);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let len = self.0.len();
        if len > N {
            return Err(PacketError::EncodeError(
                format!("FixedAsciiString length {} exceeds maximum of {} while encoding", len, N)
            ));
        }

        enc.write_bytes(self.0.as_bytes());
        if len < N {
            enc.write_zeros(N - len);
        }
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(N)?;
        let str_end = bytes.iter().position(|&b| b == 0).unwrap_or(N);
        Ok(Self(String::from_utf8(bytes[..str_end].to_vec())?))
    }
}

impl<const N: usize> Deref for FixedAsciiString<N> {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for FixedAsciiString<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> From<String> for FixedAsciiString<N> {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl<const N: usize> From<FixedAsciiString<N>> for String {
    fn from(s: FixedAsciiString<N>) -> Self {
        s.0
    }
}

impl<const N: usize> AsRef<str> for FixedAsciiString<N> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> fmt::Display for FixedAsciiString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T: PacketCodec> PacketCodec for Vec<T> {
    const SIZE: Option<usize> = None;
    const IS_OPTIONAL: bool = true;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let len = self.len();
        if len > 0 {
            enc.write_varint(len)?;
            for item in self {
                item.encode(enc)?;
            }
        }
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        if !dec.current_null_value() {
            return Ok(Vec::new())
        }
        
        let len = dec.read_varint()?;
        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            items.push(T::decode(dec)?);
        }
        Ok(items)
    }

    fn has_value(&self) -> bool {
        !self.is_empty()
    }
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct VarList<T, const MAX: usize>(pub Vec<T>);

impl<T: PacketCodec, const MAX: usize> PacketCodec for VarList<T, MAX> {
    const SIZE: Option<usize> = None;
    const IS_OPTIONAL: bool = true;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let len = self.0.len();
        if len > 0 {
            if len > MAX {
                return Err(PacketError::EncodeError(
                    format!("VarList length {} exceeds maximum of {} while encoding", len, MAX)
                ));
            }
            
            enc.write_varint(len)?;
            for item in &self.0 {
                item.encode(enc)?;
            }
        }
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        if !dec.current_null_value() {
            return Ok(Self(Vec::new()))
        }

        let len = dec.read_varint()?;
        if len < 0 {
            return Err(PacketError::DecodeError(
                format!("VarList length {} is negative while decoding", len)
            ));
        }

        if len > MAX {
            return Err(PacketError::DecodeError(
                format!("VarList length {} exceeds maximum of {} while decoding", len, MAX)
            ));
        }

        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            items.push(T::decode(dec)?);
        }
        Ok(Self(items))
    }

    fn has_value(&self) -> bool {
        !self.is_empty()
    }
}

impl<T, const MAX: usize> Deref for VarList<T, MAX> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const MAX: usize> DerefMut for VarList<T, MAX> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, const MAX: usize> From<Vec<T>> for VarList<T, MAX> {
    fn from(v: Vec<T>) -> Self {
        Self(v)
    }
}

impl<T, const MAX: usize> From<VarList<T, MAX>> for Vec<T> {
    fn from(v: VarList<T, MAX>) -> Self {
        v.0
    }
}

impl<T, const MAX: usize> AsRef<[T]> for VarList<T, MAX> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: fmt::Debug, const MAX: usize> fmt::Display for VarList<T, MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<T: PacketCodec> PacketCodec for Option<T> {
    const SIZE: Option<usize> = None;
    const IS_OPTIONAL: bool = true;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        match self {
            Some(v) => v.encode(enc),
            None => Ok(())
        }
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        if dec.current_null_value() {
            T::decode(dec).map(Some)
        } else {
            Ok(None)
        }
    }

    fn has_value(&self) -> bool {
        self.is_some()
    }
}

impl<T: PacketCodec> PacketCodec for Arc<T> {
    const SIZE: Option<usize> = T::SIZE;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        (**self).encode(enc)
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        T::decode(dec).map(Arc::new)
    }
}