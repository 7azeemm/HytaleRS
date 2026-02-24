use crate::io::decoder::Decoder;
use crate::io::encoder::Encoder;
use crate::io::errors::{PacketError, PacketResult};
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use ordered_float::OrderedFloat;
use uuid::Uuid;

const MAX_STRING_LENGTH: usize = 4_096_000;

pub trait PacketCodec: Sized + Debug {
    const SIZE: Option<usize>;
    const OPTIONAL: bool = false;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()>;
    fn decode(dec: &mut Decoder) -> PacketResult<Self>;
    fn has_value(&self) -> bool {
        true
    }
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
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
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
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
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
            v => Err(PacketError::DecodeError(format!(
                "Invalid boolean value: {}",
                v
            ))),
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
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
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
            return Err(PacketError::EncodeError(format!(
                "String length {} exceeds maximum of {} while encoding",
                len, MAX_STRING_LENGTH
            )));
        }

        enc.write_varint(len)?;
        enc.write_bytes(self.as_bytes());
        Ok(())
    }

    fn decode(decoder: &mut Decoder) -> PacketResult<Self> {
        let len = decoder.read_varint()?;

        if len > MAX_STRING_LENGTH {
            return Err(PacketError::DecodeError(format!(
                "String length {} exceeds maximum of {} while decoding",
                len, MAX_STRING_LENGTH
            )));
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
            return Err(PacketError::EncodeError(format!(
                "VarString length {} exceeds maximum of {} while encoding",
                len, MAX
            )));
        }

        enc.write_varint(len)?;
        enc.write_bytes(self.0.as_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let len = dec.read_varint()?;

        if len > MAX {
            return Err(PacketError::DecodeError(format!(
                "VarString length {} exceeds maximum of {} while decoding",
                len, MAX
            )));
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

impl<const MAX: usize> Display for VarString<MAX> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct FixedString<const N: usize>(pub String);

impl<const N: usize> PacketCodec for FixedString<N> {
    const SIZE: Option<usize> = Some(N);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let len = self.0.len();
        if len > N {
            return Err(PacketError::EncodeError(format!(
                "FixedString length {} exceeds maximum of {} while encoding",
                len, N
            )));
        }

        enc.write_bytes(self.0.as_bytes());
        if len < N {
            enc.write_bytes(&vec![0; N - len]);
        }
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(N)?;
        let str_end = bytes.iter().position(|&b| b == 0).unwrap_or(N);
        Ok(Self(String::from_utf8(bytes[..str_end].to_vec())?))
    }
}

impl<const N: usize> Deref for FixedString<N> {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for FixedString<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> From<String> for FixedString<N> {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl<const N: usize> From<FixedString<N>> for String {
    fn from(s: FixedString<N>) -> Self {
        s.0
    }
}

impl<const N: usize> AsRef<str> for FixedString<N> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> Display for FixedString<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T: PacketCodec> PacketCodec for Vec<T> {
    const SIZE: Option<usize> = None;
    const OPTIONAL: bool = true;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let len = self.len();
        let entered_opt_type = enc.add_null_bit(len != 0);

        if len > 0 {
            enc.write_varint(len)?;
            for item in self {
                item.encode(enc)?;
            }
        }

        if entered_opt_type {
            enc.leave_opt_type();
        }

        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let (present, entered_opt_type) = dec.read_null_bit();

        let items = match present {
            true => {
                let len = dec.read_varint()?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(T::decode(dec)?);
                }
                Ok(items)
            }
            false => Ok(Vec::new())
        };

        if entered_opt_type {
            dec.leave_opt_type();
        }

        items
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
    const OPTIONAL: bool = true;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let len = self.0.len();
        let entered_opt_type = enc.add_null_bit(len != 0);

        if len > 0 {
            if len > MAX {
                return Err(PacketError::EncodeError(format!(
                    "VarList length {} exceeds maximum of {} while encoding",
                    len, MAX
                )));
            }

            enc.write_varint(len)?;
            for item in &self.0 {
                item.encode(enc)?;
            }
        }

        if entered_opt_type {
            enc.leave_opt_type();
        }

        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let (present, entered_opt_type) = dec.read_null_bit();

        let items = match present {
            true => {
                let len = dec.read_varint()?;
                if len > MAX {
                    return Err(PacketError::DecodeError(format!(
                        "VarList length {} exceeds maximum of {} while decoding",
                        len, MAX
                    )));
                }

                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(T::decode(dec)?);
                }
                Ok(VarList(items))
            }
            false => Ok(VarList(Vec::new()))
        };

        if entered_opt_type {
            dec.leave_opt_type();
        }

        items
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

impl<T: Debug, const MAX: usize> Display for VarList<T, MAX> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<K: PacketCodec + Eq + Hash, V: PacketCodec> PacketCodec for HashMap<K, V> {
    const SIZE: Option<usize> = None;
    const OPTIONAL: bool = true;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let len = self.len();
        let entered_opt_type = enc.add_null_bit(len != 0);

        if len > 0 {
            enc.write_varint(len)?;
            for (k, v) in self {
                k.encode(enc)?;
                v.encode(enc)?;
            }
        }

        if entered_opt_type {
            enc.leave_opt_type();
        }

        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let (present, entered_opt_type) = dec.read_null_bit();

        let items = match present {
            true => {
                let len = dec.read_varint()?;
                let mut items = HashMap::with_capacity(len);
                for _ in 0..len {
                    let k = K::decode(dec)?;
                    let v = V::decode(dec)?;
                    items.insert(k, v);
                }
                Ok(items)
            }
            false => Ok(HashMap::new())
        };

        if entered_opt_type {
            dec.leave_opt_type();
        }

        items
    }

    fn has_value(&self) -> bool {
        !self.is_empty()
    }
}

impl<T: PacketCodec> PacketCodec for Option<T> {
    const SIZE: Option<usize> = None;
    const OPTIONAL: bool = true;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let entered_opt_type = enc.add_null_bit(self.is_some());

        let out = match self {
            Some(v) => v.encode(enc),
            None => Ok(()),
        };

        if entered_opt_type {
            enc.leave_opt_type();
        }

        out
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let (present, entered_opt_type) = dec.read_null_bit();

        let item = match present {
            true => Some(T::decode(dec)?),
            false => None,
        };

        if entered_opt_type {
            dec.leave_opt_type();
        }

        Ok(item)
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

//TODO: improve
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct FixedOption<T>(pub Option<T>);

impl<T: PacketCodec> PacketCodec for FixedOption<T> {
    const SIZE: Option<usize> = Some(T::SIZE.expect("FixedOption<T> is not Sized"));
    const OPTIONAL: bool = true;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        let entered_opt_type = enc.add_null_bit(self.0.is_some());

        let out = match &self.0 {
            Some(v) => v.encode(enc),
            None => Ok(enc.write_zeros(Self::SIZE.unwrap())),
        };

        if entered_opt_type {
            enc.leave_opt_type();
        }

        out
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let (present, entered_opt_type) = dec.read_null_bit();

        let item = match present {
            true => FixedOption(Some(T::decode(dec)?)),
            false => {
                dec.read_zeros(T::SIZE.unwrap())?;
                FixedOption(None)
            }
        };

        if entered_opt_type {
            dec.leave_opt_type();
        }

        Ok(item)
    }
}

impl<T: PacketCodec> Deref for FixedOption<T> {
    type Target = Option<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: PacketCodec> DerefMut for FixedOption<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: PacketCodec> From<Option<T>> for FixedOption<T> {
    fn from(s: Option<T>) -> Self {
        Self(s)
    }
}

impl<T: PacketCodec> From<FixedOption<T>> for Option<T> {
    fn from(s: FixedOption<T>) -> Self {
        s.0
    }
}

impl<T: PacketCodec> Display for FixedOption<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<T> Default for FixedOption<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl PacketCodec for OrderedFloat<f32> {
    const SIZE: Option<usize> = Some(4);

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_bytes(&self.0.to_le_bytes());
        Ok(())
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let bytes = dec.read_bytes(4)?;
        Ok(OrderedFloat(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])))
    }
}