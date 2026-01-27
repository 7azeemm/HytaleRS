use log::{debug, error, info};
use quinn::{ReadError, ReadExactError, RecvStream};
use tokio::time::Instant;
use uuid::Uuid;
use crate::server::core::network::connection_manager::MAX_PACKET_SIZE;
use crate::server::core::network::packet::{MAX_VARINT, MAX_VARINT_ITERATIONS};
use crate::server::core::network::packet::packet::{Packet, PacketField};
use crate::server::core::network::packet::packet_error::PacketError;

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
    pub fn read_u8(&mut self, field: &'static str) -> Result<u8, PacketError> {
        if self.pos >= self.buf.len() {
            return Err(PacketError::DecodeEOF { field });
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    #[inline]
    pub fn read_i16(&mut self, field: &'static str) -> Result<i16, PacketError> {
        let bytes = self.read_fixed_array(2, field)?;
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    pub fn read_u16(&mut self, field: &'static str) -> Result<u16, PacketError> {
        let bytes = self.read_fixed_array(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    pub fn read_u32(&mut self, field: &'static str) -> Result<u32, PacketError> {
        let bytes = self.read_fixed_array(4, field)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_i32(&mut self, field: &'static str) -> Result<i32, PacketError> {
        let bytes = self.read_fixed_array(4, field)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_f32(&mut self, field: &'static str) -> Result<f32, PacketError> {
        let bytes = self.read_fixed_array(4, field)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_f64(&mut self, field: &'static str) -> Result<f64, PacketError> {
        let bytes = self.read_fixed_array(8, field)?;
        Ok(f64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    #[inline]
    pub fn read_u128(&mut self, field: &'static str) -> Result<u128, PacketError> {
        let bytes = self.read_fixed_array(16, field)?;
        Ok(u128::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]))
    }

    #[inline]
    pub fn read_fixed_array(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], PacketError> {
        let end = self.pos.saturating_add(len);
        if end > self.buf.len() {
            return Err(PacketError::DecodeEOF { field });
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    #[inline]
    pub fn read_fixed_string(&mut self, len: usize, field: &'static str) -> Result<String, PacketError> {
        let bytes = self.read_fixed_array(len, field)?;
        let end = memchr::memchr(0, bytes).unwrap_or(len);
        String::from_utf8(bytes[..end].to_vec())
            .map_err(|_| PacketError::DecodeInvalidUtf8 { field })
    }

    #[inline]
    pub fn read_uuid(&mut self, field: &'static str) -> Result<Uuid, PacketError> {
        let bytes = self.read_fixed_array(16, field)?;
        let mut array = [0u8; 16];
        array.copy_from_slice(bytes);
        Ok(Uuid::from_bytes(array))
    }

    #[inline]
    pub fn read_offsets<const N: usize>(&mut self) -> Result<[i32; N], PacketError> {
        const FIELD: &str = "offsets";
        let mut offsets = [0i32; N];
        for offset in &mut offsets {
            *offset = self.read_i32(FIELD)?;
        }
        Ok(offsets)
    }

    #[inline]
    pub fn read_var_string(&self, offset: i32, field: &'static str) -> Result<String, PacketError> {
        let slice = self.read_var_field(offset, field)?;
        String::from_utf8(slice.to_vec())
            .map_err(|_| PacketError::DecodeInvalidUtf8 { field })
    }

    #[inline]
    pub fn read_var_bytes(&self, offset: i32, field: &'static str) -> Result<Vec<u8>, PacketError> {
        self.read_var_field(offset, field).map(|slice| slice.to_vec())
    }

    #[inline]
    fn read_var_primitive(&self, offset: i32, size: usize, field: &'static str) -> Result<&'a [u8], PacketError> {
        if offset < 0 {
            return Err(PacketError::DecodeNegativeOffset { field, offset });
        }
        let offset = offset as usize;
        let var_block = self.var_block();
        let end = offset.saturating_add(size);
        if end > var_block.len() {
            return Err(PacketError::DecodeEOF { field });
        }
        Ok(&var_block[offset..offset + size])
    }

    #[inline]
    pub fn read_var_u8(&self, offset: i32, field: &'static str) -> Result<u8, PacketError> {
        Ok(self.read_var_primitive(offset, 1, field)?[0])
    }

    #[inline]
    pub fn read_var_i16(&self, offset: i32, field: &'static str) -> Result<i16, PacketError> {
        let bytes = self.read_var_primitive(offset, 2, field)?;
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    pub fn read_var_u16(&self, offset: i32, field: &'static str) -> Result<u16, PacketError> {
        let bytes = self.read_var_primitive(offset, 2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    pub fn read_var_i32(&self, offset: i32, field: &'static str) -> Result<i32, PacketError> {
        let bytes = self.read_var_primitive(offset, 4, field)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_var_u32(&self, offset: i32, field: &'static str) -> Result<u32, PacketError> {
        let bytes = self.read_var_primitive(offset, 4, field)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_var_i64(&self, offset: i32, field: &'static str) -> Result<i64, PacketError> {
        let b = self.read_var_primitive(offset, 8, field)?;
        Ok(i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    #[inline]
    pub fn read_var_u64(&self, offset: i32, field: &'static str) -> Result<u64, PacketError> {
        let bytes = self.read_var_primitive(offset, 8, field)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7]
        ]))
    }

    #[inline]
    pub fn read_var_f32(&self, offset: i32, field: &'static str) -> Result<f32, PacketError> {
        let bytes = self.read_var_primitive(offset, 4, field)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline]
    pub fn read_var_f64(&self, offset: i32, field: &'static str) -> Result<f64, PacketError> {
        let bytes = self.read_var_primitive(offset, 8, field)?;
        Ok(f64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7]
        ]))
    }

    #[inline]
    pub fn read_var_u128(&self, offset: i32, field: &'static str) -> Result<u128, PacketError> {
        let b = self.read_var_primitive(offset, 16, field)?;
        Ok(u128::from_le_bytes([
            b[0], b[1], b[2], b[3],
            b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11],
            b[12], b[13], b[14], b[15],
        ]))
    }

    #[inline]
    pub fn read_opt_string(
        &self,
        nulls: u8,
        bit: u8,
        offset: i32,
        field: &'static str,
    ) -> Result<Option<String>, PacketError> {
        if is_null_bit_set(nulls, bit) {
            self.read_var_string(offset, field).map(Some)
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
        field: &'static str,
    ) -> Result<Option<Vec<u8>>, PacketError> {
        if is_null_bit_set(nulls, bit) {
            self.read_var_bytes(offset, field).map(Some)
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
        field: &'static str,
    ) -> Result<Option<&'a [u8]>, PacketError> {
        if is_null_bit_set(nulls, bit) {
            self.read_var_primitive(offset, size, field).map(Some)
        } else {
            Ok(None)
        }
    }

    #[inline]
    pub fn read_opt_u8(&self, nulls: u8, bit: u8, offset: i32, field: &'static str) -> Result<Option<u8>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 1, field)
            .map(|opt| opt.map(|b| b[0]))
    }

    #[inline]
    pub fn read_opt_i16(&self, nulls: u8, bit: u8, offset: i32, field: &'static str) -> Result<Option<i16>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 2, field)
            .map(|opt| opt.map(|b| i16::from_le_bytes([b[0], b[1]])))
    }

    #[inline]
    pub fn read_opt_u16(&self, nulls: u8, bit: u8, offset: i32, field: &'static str) -> Result<Option<u16>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 2, field)
            .map(|opt| opt.map(|b| u16::from_le_bytes([b[0], b[1]])))
    }

    #[inline]
    pub fn read_opt_i32(&self, nulls: u8, bit: u8, offset: i32, field: &'static str) -> Result<Option<i32>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 4, field)
            .map(|opt| opt.map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    #[inline]
    pub fn read_opt_u32(&self, nulls: u8, bit: u8, offset: i32, field: &'static str) -> Result<Option<u32>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 4, field)
            .map(|opt| opt.map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    #[inline]
    pub fn read_opt_i64(&self, nulls: u8, bit: u8, offset: i32, field: &'static str) -> Result<Option<i64>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 8, field)
            .map(|opt| opt.map(|b| i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
    }

    #[inline]
    pub fn read_opt_u64(&self, nulls: u8, bit: u8, offset: i32, field: &'static str) -> Result<Option<u64>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 8, field)
            .map(|opt| opt.map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
    }

    #[inline]
    pub fn read_opt_f32(&self, nulls: u8, bit: u8, offset: i32, field: &'static str) -> Result<Option<f32>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 4, field)
            .map(|opt| opt.map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    #[inline]
    pub fn read_opt_f64(&self, nulls: u8, bit: u8, offset: i32, field: &'static str) -> Result<Option<f64>, PacketError> {
        self.read_opt_var_primitive(nulls, bit, offset, 8, field)
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
    fn read_var_field(&self, offset: i32, field: &'static str) -> Result<&'a [u8], PacketError> {
        if offset < 0 {
            return Err(PacketError::DecodeNegativeOffset { field, offset });
        }
        let offset = offset as usize;
        let var_block = self.var_block();

        if offset >= var_block.len() {
            return Err(PacketError::DecodeOutOfBounds {
                field,
                offset: offset as i32,
                available: var_block.len(),
            });
        }

        let (len, data_pos) = read_varint_at(var_block, offset, field)?;

        let end = data_pos + len;
        if end > var_block.len() {
            return Err(PacketError::DecodeEOF { field });
        }

        Ok(&var_block[data_pos..end])
    }

    #[inline]
    pub fn read_varint_string(&mut self, field: &'static str) -> Result<String, PacketError> {
        let string_bytes = self.read_varint_bytes(field)?;
        String::from_utf8(string_bytes)
            .map_err(|_| PacketError::DecodeInvalidUtf8 { field })
    }

    #[inline]
    pub fn read_opt_varint_string(&mut self, nulls: u8, bit: u8, field: &'static str) -> Result<Option<String>, PacketError> {
        if is_null_bit_set(nulls, bit) {
            let string_bytes = self.read_varint_bytes(field)?;
            let string = String::from_utf8(string_bytes)
                .map_err(|_| PacketError::DecodeInvalidUtf8 { field })?;
            Ok(Some(string))
        } else {
            Ok(None)
        }
    }

    #[inline]
    pub fn read_varint_bytes(&mut self, field: &'static str) -> Result<Vec<u8>, PacketError> {
        let (len, new_pos) = read_varint_at(self.buf, self.pos, field)?;
        self.pos = new_pos;

        let end = self.pos + len;
        if end > self.buf.len() {
            return Err(PacketError::DecodeEOF { field });
        }

        let result = self.buf[self.pos..end].to_vec();
        self.pos = end;

        Ok(result)
    }
}

#[inline]
pub fn is_null_bit_set(nulls: u8, bit: u8) -> bool {
    (nulls & (1 << bit)) != 0
}

#[inline]
pub fn read_varint_at(buf: &[u8], mut pos: usize, field: &'static str) -> Result<(usize, usize), PacketError> {
    let mut value = 0usize;
    let mut shift = 0u32;
    let len = buf.len();

    for _ in 0..MAX_VARINT_ITERATIONS {
        if pos >= len {
            return Err(PacketError::DecodeEOF { field });
        }

        let byte = buf[pos];
        pos += 1;
        value |= ((byte & 0x7F) as usize) << shift;

        if byte & 0x80 == 0 {
            if value > MAX_VARINT {
                return Err(PacketError::DecodeVarIntOverflow { field });
            }
            return Ok((value, pos));
        }

        shift += 7;
    }

    Err(PacketError::DecodeVarIntOverflow { field })
}

/// Read framed packet from stream
/// Returns: (packet_id, body_bytes)
pub async fn read_framed_packet(recv: &mut RecvStream) -> Result<(u32, Vec<u8>), PacketError> {
    let mut header = [0u8; 8];

    recv.read_exact(&mut header).await.map_err(|err| map_read_error(err))?;

    let payload_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let packet_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

    if payload_len <= 0 || payload_len > MAX_PACKET_SIZE {
        return Err(PacketError::DecodeInvalidPayloadLength {
            size: payload_len,
            min: 0,
            max: MAX_PACKET_SIZE
        })
    }
    let payload_len = payload_len as usize;

    let mut payload = vec![0u8; payload_len];
    recv.read_exact(&mut payload).await.map_err(|err| map_read_error(err))?;

    Ok((packet_id, payload))
}

#[inline]
fn map_read_error(err: ReadExactError) -> PacketError {
    match err {
        ReadExactError::ReadError(read_err) => match read_err {
            ReadError::ConnectionLost(_) | ReadError::ClosedStream => PacketError::ConnectionLost,
            _ => PacketError::Error { reason: "Failed to read packet", error: read_err.to_string() },
        },
        _ => PacketError::Error { reason: "Failed to read packet", error: err.to_string() },
    }
}
