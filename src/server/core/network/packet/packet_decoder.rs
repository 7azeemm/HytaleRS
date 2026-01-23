use log::{debug, error, info};
use tokio::time::Instant;
use uuid::Uuid;
use crate::server::core::network::packet::packet::{Packet, PacketField};
use crate::server::core::network::packet::packet_error::PacketError;

const MAX_FIELD_LENGTH: usize = 32768;

pub struct PacketDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PacketDecoder<'a> {
    #[inline]
    pub fn decode<P: Packet>(data: &[u8]) -> Option<P> {
        let start_time = Instant::now();
        let packet = match P::decode(data) {
            Ok(p) => p,
            Err(err) => {
                error!("Failed to decode packet 0x{:02X}: {}", P::packet_id(), err);
                return None
            }
        };
        let end_time = start_time.elapsed();

        info!("Decoded Packet 0x{:02X} in {:?}", P::packet_id(), end_time);
        dbg!(&packet);
        Some(packet)
    }

    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn read_null_bits(&mut self) -> Result<u8, PacketError> {
        self.read_u8("null_bits")
    }

    #[inline]
    pub fn read_u8(&mut self, name: &'static str) -> Result<u8, PacketError> {
        if self.pos >= self.buf.len() {
            return Err(PacketError::Decode(format!("EOF in {}", name)));
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    #[inline]
    pub fn read_i16(&mut self, name: &'static str) -> Result<i16, PacketError> {
        let bytes = self.read_fixed_array(2, name)?;
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    pub fn read_u16(&mut self, name: &'static str) -> Result<u16, PacketError> {
        let bytes = self.read_fixed_array(2, name)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    pub fn read_u32(&mut self, name: &'static str) -> Result<u32, PacketError> {
        let bytes = self.read_fixed_array(4, name)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_i32(&mut self, name: &'static str) -> Result<i32, PacketError> {
        let bytes = self.read_fixed_array(4, name)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_f32(&mut self, name: &'static str) -> Result<f32, PacketError> {
        let bytes = self.read_fixed_array(4, name)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_f64(&mut self, name: &'static str) -> Result<f64, PacketError> {
        let bytes = self.read_fixed_array(8, name)?;
        Ok(f64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    #[inline]
    pub fn read_u128(&mut self, name: &'static str) -> Result<u128, PacketError> {
        let bytes = self.read_fixed_array(16, name)?;
        Ok(u128::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]))
    }

    #[inline]
    pub fn read_fixed_array(&mut self, len: usize, name: &'static str) -> Result<&'a [u8], PacketError> {
        let end = self.pos.checked_add(len)
            .ok_or_else(|| PacketError::Decode(format!("Integer overflow while reading {}", name)))?;
        if end > self.buf.len() {
            return Err(PacketError::Decode(format!(
                "Not enough data to read {} (needs {} bytes, {} available)",
                name,
                len,
                self.buf.len() - self.pos
            )));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    #[inline]
    pub fn read_fixed_string(&mut self, len: usize, name: &'static str) -> Result<String, PacketError> {
        let bytes = self.read_fixed_array(len, name)?;
        let end = memchr::memchr(0, bytes).unwrap_or(len);
        String::from_utf8(bytes[..end].to_vec())
            .map_err(|e| PacketError::Utf8(format!("Invalid UTF-8 in {}: {}", name, e)))
    }

    #[inline]
    pub fn read_uuid(&mut self, name: &'static str) -> Result<Uuid, PacketError> {
        let bytes = self.read_fixed_array(16, name)?;
        let mut array = [0u8; 16];
        array.copy_from_slice(bytes);
        Ok(Uuid::from_bytes(array))
    }

    #[inline]
    pub fn read_offsets<const N: usize>(&mut self) -> Result<[i32; N], PacketError> {
        let mut offsets = [0i32; N];
        for offset in &mut offsets {
            *offset = self.read_i32("offsets")?;
        }
        Ok(offsets)
    }

    #[inline]
    pub fn read_var_string(&self, offset: i32, name: &'static str) -> Result<String, PacketError> {
        let slice = self.read_var_field(offset, name)?;
        String::from_utf8(slice.to_vec())
            .map_err(|e| PacketError::Utf8(format!("Invalid UTF-8 in {}: {}", name, e)))
    }

    #[inline]
    pub fn read_var_bytes(&self, offset: i32, name: &'static str) -> Result<Vec<u8>, PacketError> {
        self.read_var_field(offset, name).map(|slice| slice.to_vec())
    }

    #[inline]
    fn read_var_primitive(&self, offset: i32, size: usize, name: &'static str) -> Result<&'a [u8], PacketError> {
        if offset < 0 {
            return Err(PacketError::Decode(format!("Negative offset in {}", name)));
        }
        let offset = offset as usize;
        let var = self.var_block();
        if offset.checked_add(size).ok_or_else(|| PacketError::Decode(format!("Overflow in {name}")))? > var.len() {
            return Err(PacketError::Decode(format!("EOF while reading {} at offset {}", name, offset)));
        }
        Ok(&var[offset..offset + size])
    }

    #[inline]
    pub fn read_var_u8(&self, offset: i32, name: &'static str) -> Result<u8, PacketError> {
        Ok(self.read_var_primitive(offset, 1, name)?[0])
    }

    #[inline]
    pub fn read_var_i16(&self, offset: i32, name: &'static str) -> Result<i16, PacketError> {
        let b = self.read_var_primitive(offset, 2, name)?;
        Ok(i16::from_le_bytes([b[0], b[1]]))
    }

    #[inline]
    pub fn read_var_u16(&self, offset: i32, name: &'static str) -> Result<u16, PacketError> {
        let b = self.read_var_primitive(offset, 2, name)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    #[inline]
    pub fn read_var_i32(&self, offset: i32, name: &'static str) -> Result<i32, PacketError> {
        let b = self.read_var_primitive(offset, 4, name)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    pub fn read_var_u32(&self, offset: i32, name: &'static str) -> Result<u32, PacketError> {
        let b = self.read_var_primitive(offset, 4, name)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    pub fn read_var_i64(&self, offset: i32, name: &'static str) -> Result<i64, PacketError> {
        let b = self.read_var_primitive(offset, 8, name)?;
        Ok(i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    #[inline]
    pub fn read_var_u64(&self, offset: i32, name: &'static str) -> Result<u64, PacketError> {
        let b = self.read_var_primitive(offset, 8, name)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    #[inline]
    pub fn read_var_f32(&self, offset: i32, name: &'static str) -> Result<f32, PacketError> {
        let b = self.read_var_primitive(offset, 4, name)?;
        Ok(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    pub fn read_var_f64(&self, offset: i32, name: &'static str) -> Result<f64, PacketError> {
        let b = self.read_var_primitive(offset, 8, name)?;
        Ok(f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    #[inline]
    pub fn read_opt_string(
        &self,
        nulls: u8,
        bit: u8,
        offset: i32,
        name: &'static str,
    ) -> Result<Option<String>, PacketError> {
        if is_null_bit_set(nulls, bit) {
            self.read_var_string(offset, name).map(Some)
        } else {
            Ok(None)
        }
    }

    #[inline]
    pub fn read_opt_bytes(
        &self,
        nulls: u8,
        bit: u8,
        offset: i32,
        name: &'static str,
    ) -> Result<Option<Vec<u8>>, PacketError> {
        if is_null_bit_set(nulls, bit) {
            self.read_var_bytes(offset, name).map(Some)
        } else {
            Ok(None)
        }
    }

    #[inline]
    fn read_opt_var_primitive(
        &self,
        nulls: u8,
        bit: u8,
        offset: i32,
        size: usize,
        name: &'static str,
    ) -> Result<Option<&'a [u8]>, PacketError> {
        if is_null_bit_set(nulls, bit) {
            self.read_var_primitive(offset, size, name).map(Some)
        } else {
            Ok(None)
        }
    }

    #[inline]
    pub fn read_opt_u8(&self, nulls: u8, bit: u8, offset: i32, name: &'static str) -> Result<Option<u8>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 1, name)
            .map(|opt| opt.map(|b| b[0]))
    }

    #[inline]
    pub fn read_opt_i16(&self, nulls: u8, bit: u8, offset: i32, name: &'static str) -> Result<Option<i16>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 2, name)
            .map(|opt| opt.map(|b| i16::from_le_bytes([b[0], b[1]])))
    }

    #[inline]
    pub fn read_opt_u16(&self, nulls: u8, bit: u8, offset: i32, name: &'static str) -> Result<Option<u16>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 2, name)
            .map(|opt| opt.map(|b| u16::from_le_bytes([b[0], b[1]])))
    }

    #[inline]
    pub fn read_opt_i32(&self, nulls: u8, bit: u8, offset: i32, name: &'static str) -> Result<Option<i32>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 4, name)
            .map(|opt| opt.map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    #[inline]
    pub fn read_opt_u32(&self, nulls: u8, bit: u8, offset: i32, name: &'static str) -> Result<Option<u32>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 4, name)
            .map(|opt| opt.map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    #[inline]
    pub fn read_opt_i64(&self, nulls: u8, bit: u8, offset: i32, name: &'static str) -> Result<Option<i64>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 8, name)
            .map(|opt| opt.map(|b| i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
    }

    #[inline]
    pub fn read_opt_u64(&self, nulls: u8, bit: u8, offset: i32, name: &'static str) -> Result<Option<u64>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 8, name)
            .map(|opt| opt.map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
    }

    #[inline]
    pub fn read_opt_f32(&self, nulls: u8, bit: u8, offset: i32, name: &'static str) -> Result<Option<f32>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 4, name)
            .map(|opt| opt.map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    #[inline]
    pub fn read_opt_f64(&self, nulls: u8, bit: u8, offset: i32, name: &'static str) -> Result<Option<f64>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 8, name)
            .map(|opt| opt.map(|b| f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
    }

    #[inline]
    pub fn read_opt_field<T: PacketField>(
        &mut self,
        nulls: u8,
        bit: u8,
        offset: i32,
    ) -> Result<Option<T>, PacketError> {
        if is_null_bit_set(nulls, bit) {
            T::decode(self, offset).map(Some)
        } else {
            Ok(None)
        }
    }

    #[inline]
    pub fn var_block(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    #[inline]
    fn read_var_field(&self, offset: i32, name: &'static str) -> Result<&'a [u8], PacketError> {
        if offset < 0 {
            return Err(PacketError::Decode(format!("Negative offset in {}", name)));
        }
        let offset = offset as usize;
        let var_block = self.var_block();

        if offset >= var_block.len() {
            return Err(PacketError::Decode(format!("Offset out of bounds for {}", name)));
        }

        let (len, data_pos) = read_varint_at(var_block, offset)?;

        if len > MAX_FIELD_LENGTH {
            return Err(PacketError::Decode(format!("{} too long: {} > {}", name, len, MAX_FIELD_LENGTH)));
        }

        let end = data_pos + len;
        if end > var_block.len() {
            return Err(PacketError::Decode(format!("Field overflow for {}", name)));
        }

        Ok(&var_block[data_pos..end])
    }
}

#[inline]
pub fn is_null_bit_set(nulls: u8, bit: u8) -> bool {
    (nulls & (1 << bit)) != 0
}

#[inline]
pub fn read_varint_at(buf: &[u8], mut pos: usize) -> Result<(usize, usize), PacketError> {
    let mut value = 0usize;
    let mut shift = 0u32;
    let len = buf.len();

    loop {
        if pos >= len {
            return Err(PacketError::Decode("VarInt overflow".into()));
        }

        let byte = buf[pos];
        pos += 1;
        value |= ((byte & 0x7F) as usize) << shift;

        if byte & 0x80 == 0 {
            return Ok((value, pos));
        }

        shift += 7;
        if shift > 28 {
            return Err(PacketError::Decode("VarInt too large".into()));
        }
    }
}