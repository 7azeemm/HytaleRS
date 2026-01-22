use std::io::Write;
use crate::server::core::network::packet::packet_codec::CodecError;
use crate::server::core::network::packet::packet::{Packet, PacketField};
use uuid::Uuid;

pub struct PacketDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PacketDecoder<'a> {
    #[inline(always)]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Read null bits (first byte)
    #[inline(always)]
    pub fn read_null_bits(&mut self) -> Result<NullBits, CodecError> {
        Ok(NullBits(self.read_u8("null_bits")?))
    }

    #[inline(always)]
    pub fn read_u8(&mut self, name: &'static str) -> Result<u8, CodecError> {
        if self.pos >= self.buf.len() {
            return Err(CodecError::Decode(format!("EOF while reading {}", name)));
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    #[inline(always)]
    pub fn read_i16(&mut self, name: &'static str) -> Result<i16, CodecError> {
        let bytes = self.read_fixed_array(2, name)?;
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[inline(always)]
    pub fn read_u32(&mut self, name: &'static str) -> Result<u32, CodecError> {
        let bytes = self.read_fixed_array(4, name)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline(always)]
    pub fn read_i32(&mut self, name: &'static str) -> Result<i32, CodecError> {
        let bytes = self.read_fixed_array(4, name)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline(always)]
    pub fn read_f32(&mut self, name: &'static str) -> Result<f32, CodecError> {
        let bytes = self.read_fixed_array(4, name)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline(always)]
    pub fn read_f64(&mut self, name: &'static str) -> Result<f64, CodecError> {
        let bytes = self.read_fixed_array(8, name)?;
        Ok(f64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    #[inline(always)]
    pub fn read_u128(&mut self, name: &'static str) -> Result<u128, CodecError> {
        let bytes = self.read_fixed_array(16, name)?;
        let mut array = [0u8; 16];
        array.copy_from_slice(bytes);
        Ok(u128::from_le_bytes(array))
    }

    /// Read fixed-size byte array
    #[inline(always)]
    pub fn read_fixed_array(&mut self, len: usize, name: &'static str) -> Result<&'a [u8], CodecError> {
        let end = self.pos + len;
        if end > self.buf.len() {
            return Err(CodecError::Decode(format!("Not enough data to read {} (needs {} bytes, {} available)", name, len, self.buf.len() - self.pos)));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read fixed-size null-terminated string
    #[inline(always)]
    pub fn read_fixed_string(&mut self, len: usize, name: &'static str) -> Result<String, CodecError> {
        let bytes = self.read_fixed_array(len, name)?;
        let end = memchr::memchr(0, bytes).unwrap_or(len);
        String::from_utf8(bytes[..end].to_vec())
            .map_err(|_| CodecError::Decode(format!("Invalid UTF-8 in {}", name)))
    }

    /// Read UUID
    #[inline(always)]
    pub fn read_uuid(&mut self, name: &'static str) -> Result<Uuid, CodecError> {
        let bytes = self.read_fixed_array(16, name)?;
        let mut array = [0u8; 16];
        array.copy_from_slice(bytes);
        Ok(Uuid::from_bytes(array))
    }

    /// Read offsets for variable fields
    #[inline(always)]
    pub fn read_offsets<const N: usize>(&mut self, name: &'static str) -> Result<[i32; N], CodecError> {
        let mut offsets = [0i32; N];
        for offset in &mut offsets {
            *offset = self.read_i32(name)?;
        }
        Ok(offsets)
    }

    /// Get variable string from offset - automatically handles None if offset < 0
    #[inline(always)]
    pub fn read_var_string(&self, offset: i32, name: &'static str) -> Result<String, CodecError> {
        let offset = cast_offset(offset, name)?;
        let slice = self.read_var_field(offset, name)?;
        String::from_utf8(slice.to_vec())
            .map_err(|_| CodecError::Decode(format!("Invalid UTF-8 in {}", name)))
    }

    /// Get variable bytes from offset - automatically handles None if offset < 0
    #[inline(always)]
    pub fn read_var_bytes(&self, offset: i32, name: &'static str) -> Result<Vec<u8>, CodecError> {
        let offset = cast_offset(offset, name)?;
        self.read_var_field(offset, name).map(|slice| slice.to_vec())
    }

    #[inline(always)]
    pub fn read_var_u8(&self, offset: i32, name: &'static str) -> Result<u8, CodecError> {
        let offset = cast_offset(offset, name)?;
        let var = self.var_block();
        if offset >= var.len() {
            return Err(CodecError::Decode(format!("EOF while reading {} at offset {}", name, offset)));
        }
        Ok(var[offset])
    }

    #[inline(always)]
    pub fn read_var_i16(&self, offset: i32, name: &'static str) -> Result<i16, CodecError> {
        let offset = cast_offset(offset, name)?;
        let var = self.var_block();
        if offset + 2 > var.len() {
            return Err(CodecError::Decode(format!("EOF while reading {} at offset {}", name, offset)));
        }
        Ok(i16::from_le_bytes([var[offset], var[offset + 1]]))
    }

    #[inline(always)]
    pub fn read_var_u16(&self, offset: i32, name: &'static str) -> Result<u16, CodecError> {
        let offset = cast_offset(offset, name)?;
        let var = self.var_block();
        if offset + 2 > var.len() {
            return Err(CodecError::Decode(format!("EOF while reading {} at offset {}", name, offset)));
        }
        Ok(u16::from_le_bytes([var[offset], var[offset + 1]]))
    }

    #[inline(always)]
    pub fn read_var_i32(&self, offset: i32, name: &'static str) -> Result<i32, CodecError> {
        let offset = cast_offset(offset, name)?;
        let var = self.var_block();
        if offset + 4 > var.len() {
            return Err(CodecError::Decode(format!("EOF while reading {} at offset {}", name, offset)));
        }
        Ok(i32::from_le_bytes([var[offset], var[offset + 1], var[offset + 2], var[offset + 3]]))
    }

    #[inline(always)]
    pub fn read_var_u32(&self, offset: i32, name: &'static str) -> Result<u32, CodecError> {
        let offset = cast_offset(offset, name)?;
        let var = self.var_block();
        if offset + 4 > var.len() {
            return Err(CodecError::Decode(format!("EOF while reading {} at offset {}", name, offset)));
        }
        Ok(u32::from_le_bytes([var[offset], var[offset + 1], var[offset + 2], var[offset + 3]]))
    }

    #[inline(always)]
    pub fn read_var_f32(&self, offset: i32, name: &'static str) -> Result<f32, CodecError> {
        Ok(f32::from_le_bytes([
            self.read_var_u8(offset, name)?,
            self.read_var_u8(offset + 1, name)?,
            self.read_var_u8(offset + 2, name)?,
            self.read_var_u8(offset + 3, name)?,
        ]))
    }

    #[inline(always)]
    pub fn read_var_f64(&self, offset: i32, name: &'static str) -> Result<f64, CodecError> {
        Ok(f64::from_le_bytes([
            self.read_var_u8(offset, name)?,
            self.read_var_u8(offset + 1, name)?,
            self.read_var_u8(offset + 2, name)?,
            self.read_var_u8(offset + 3, name)?,
            self.read_var_u8(offset + 4, name)?,
            self.read_var_u8(offset + 5, name)?,
            self.read_var_u8(offset + 6, name)?,
            self.read_var_u8(offset + 7, name)?,
        ]))
    }

    /// Get remaining data as variable block
    #[inline(always)]
    pub fn var_block(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Get variable field slice
    #[inline(always)]
    fn read_var_field(&self, offset: usize, name: &'static str) -> Result<&'a [u8], CodecError> {
        let var_block = self.var_block();

        if offset >= var_block.len() {
            return Err(CodecError::Decode(format!("Offset out of bounds for {}", name)));
        }

        let (len, data_pos) = read_varint_at(var_block, offset)?;

        if len > 32768 {
            return Err(CodecError::Decode(format!("{} too long: {} > 32768", name, len)));
        }

        let end = data_pos + len;
        if end > var_block.len() {
            return Err(CodecError::Decode(format!("Field overflow for {}", name)));
        }

        Ok(&var_block[data_pos..end])
    }
}

pub struct NullBits(u8);

impl NullBits {
    /// Check if bit N is set (0-7)
    #[inline(always)]
    pub fn is_set(&self, bit: u8) -> bool {
        (self.0 & (1 << bit)) != 0
    }

    /// Get raw bits
    #[inline(always)]
    pub fn bits(&self) -> u8 {
        self.0
    }
}

#[inline(always)]
pub fn cast_offset(offset: i32, name: &'static str) -> Result<usize, CodecError> {
    if offset < 0 {
        return Err(CodecError::Decode(format!("Negative offset in {}", name)));
    }
    Ok(offset as usize)
}

#[inline(always)]
fn read_varint_at(buf: &[u8], mut pos: usize) -> Result<(usize, usize), CodecError> {
    let mut value = 0usize;
    let mut shift = 0u32;
    let len = buf.len();

    loop {
        if pos >= len {
            return Err(CodecError::Decode("VarInt overflow".into()));
        }

        let byte = buf[pos];
        pos += 1;
        value |= ((byte & 0x7F) as usize) << shift;

        if byte & 0x80 == 0 {
            return Ok((value, pos));
        }

        shift += 7;
        if shift > 28 {
            return Err(CodecError::Decode("VarInt too large".into()));
        }
    }
}

#[derive(Debug)]
pub struct Connect {
    pub protocol_hash: String,
    pub client_type: u8,
    pub uuid: Uuid,
    pub language: Option<String>,
    pub identity_token: Option<String>,
    pub username: String,
    pub referral_data: Option<Vec<u8>>,
    pub referral_source: Option<HostAddress>
}

impl Packet for Connect {
    fn packet_id(&self) -> u32 {
        0x00
    }

    fn encode(&self, _: &mut dyn Write) -> std::io::Result<()> {
        unimplemented!("Server doesn't send Connect")
    }

    fn decode(buf: &[u8]) -> Result<Self, CodecError> {
        let mut dec = PacketDecoder::new(&buf);

        // Read fixed header
        let nulls = dec.read_null_bits()?;
        let protocol_hash = dec.read_fixed_string(64, "protocol_hash")?;
        let client_type = dec.read_u8("client_type")?;
        let uuid = dec.read_uuid("uuid")?;

        // Read offsets (5 variable fields)
        let offsets = dec.read_offsets::<5>("offsets")?;

        // Decode variable fields
        let language = match nulls.is_set(0) {
            true => Some(dec.read_var_string(offsets[0], "language")?),
            false => None
        };

        let identity_token = match nulls.is_set(1) {
            true => Some(dec.read_var_string(offsets[1], "identity_token")?),
            false => None
        };

        let username = dec.read_var_string(offsets[2], "username")?;

        let referral_data = match nulls.is_set(2) {
            true => Some(dec.read_var_bytes(offsets[3], "referral_data")?),
            false => None
        };

        let referral_source = match nulls.is_set(3) {
            true => Some(HostAddress::decode(&mut dec, offsets[4])?),
            false => None
        };

        Ok(Self {
            protocol_hash,
            client_type,
            uuid,
            language,
            identity_token,
            username,
            referral_data,
            referral_source
        })
    }
}

#[derive(Debug)]
pub struct HostAddress {
    pub host: String,
    pub port: i16
}

impl PacketField for HostAddress {
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()> {
        unimplemented!()
    }

    fn decode(dec: &mut PacketDecoder, offset: i32) -> Result<Self, CodecError> {
        let port = dec.read_var_i16(offset, "port")?;
        let host = dec.read_var_string(offset + 2, "host")?;
        Ok(Self { host, port })
    }
}