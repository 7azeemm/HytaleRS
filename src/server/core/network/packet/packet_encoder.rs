use log::{error, info};
use tokio::time::Instant;
use crate::server::core::network::packet::packet::{Packet, PacketField};
use crate::server::core::network::packet::packet_error::{PacketError};
use uuid::Uuid;
use crate::server::core::network::connection_manager::MAX_PACKET_SIZE;
use crate::server::core::network::packet::{MAX_STRING_LEN};

pub struct PacketEncoder<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> PacketEncoder<'a> {
    #[inline]
    pub fn encode<P: Packet>(packet: &P) -> Option<Vec<u8>> {
        let start_time = Instant::now();
        let mut body_buf = Vec::with_capacity(512);

        if let Err(err) = packet.encode(&mut body_buf) {
            error!("Failed to encode packet 0x{:02X}: {}", P::packet_id(), err);
            return None
        }

        let packet_id = P::packet_id();
        let payload_len = body_buf.len();

        if payload_len > MAX_PACKET_SIZE as usize {
            error!("Packet payload {} exceeds max size {}", payload_len, MAX_PACKET_SIZE);
            return None
        }

        let mut out = Vec::with_capacity(8 + payload_len);
        out.extend_from_slice(&(payload_len as u32).to_le_bytes());
        out.extend_from_slice(&packet_id.to_le_bytes());
        out.extend_from_slice(&body_buf);

        let end_time = start_time.elapsed();
        info!("Encoded Packet 0x{:02X} in {:?}", packet_id, end_time);

        Some(out)
    }

    #[inline]
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn write_null_bits(&mut self, nulls: u8) {
        self.write_u8(nulls);
    }

    #[inline]
    pub fn write_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    #[inline]
    pub fn write_i16(&mut self, val: i16) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_u16(&mut self, val: u16) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_i32(&mut self, val: i32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_f32(&mut self, val: f32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_f64(&mut self, val: f64) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_u128(&mut self, val: u128) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_fixed_array(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    #[inline]
    pub fn write_fixed_string(&mut self, s: &str, len: usize, field: &'static str) -> Result<(), PacketError> {
        let s_len = s.len();
        if s_len > len {
            return Err(PacketError::EncodeStringTooLong {
                field,
                len: s.len(),
                max: len,
            });
        }
        self.buf.extend_from_slice(s.as_bytes());
        if s_len < len {
            self.buf.resize(self.buf.len() + (len - s_len), 0);
        }
        Ok(())
    }

    #[inline]
    pub fn write_uuid(&mut self, uuid: Uuid) {
        self.buf.extend_from_slice(uuid.as_bytes());
    }

    #[inline]
    pub fn reserve_offsets<'s, const N: usize>(&'s mut self) -> Result<OffsetReserver<'s, 'a, N>, PacketError> {
        let pos = self.pos();
        self.buf.resize(self.buf.len() + N * 4, 0);
        Ok(OffsetReserver {
            encoder: self,
            pos,
            offsets: [0i32; N],
            count: 0,
        })
    }

    #[inline]
    pub fn write_var_string(&mut self, s: &str, field: &'static str) -> Result<(), PacketError> {
        if s.len() > MAX_STRING_LEN {
            return Err(PacketError::EncodeStringTooLong {
                field,
                len: s.len(),
                max: MAX_STRING_LEN,
            });
        }
        write_varint(self.buf, s.len())?;
        self.buf.extend_from_slice(s.as_bytes());
        Ok(())
    }

    #[inline]
    pub fn write_var_bytes(&mut self, data: &[u8]) -> Result<(), PacketError> {
        write_varint(&mut self.buf, data.len())?;
        self.buf.extend_from_slice(data);
        Ok(())
    }

    #[inline]
    pub fn write_var_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    #[inline]
    pub fn write_var_i16(&mut self, val: i16) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_var_u16(&mut self, val: u16) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_var_i32(&mut self, val: i32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_var_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_var_i64(&mut self, val: i64) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_var_u64(&mut self, val: u64) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_var_f32(&mut self, val: f32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_var_f64(&mut self, val: f64) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_var_u128(&mut self, val: u128) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn pos(&self) -> i32 {
        self.buf.len() as i32
    }
}

/// Helper for writing variable field offsets
pub struct OffsetReserver<'a, 'b, const N: usize> {
    encoder: &'a mut PacketEncoder<'b>,
    pos: i32,                  // Position where offsets start
    offsets: [i32; N],         // Offset values to write back
    count: usize,              // How many offsets have been recorded
}

impl<'a, 'b, const N: usize> OffsetReserver<'a, 'b, N> {
    /// Record offset before writing a variable field
    #[inline]
    fn record_offset(&mut self) -> Result<i32, PacketError> {
        if self.count >= N {
            return Err(PacketError::EncodeTooManyOffsets {
                count: self.count,
                expected: N,
            });
        }
        let offset = self.encoder.pos() - (self.pos + (N as i32 * 4));
        self.offsets[self.count] = offset;
        self.count += 1;
        Ok(offset)
    }

    /// Record a -1 offset for a None field
    #[inline]
    fn record_none(&mut self) -> Result<(), PacketError> {
        if self.count >= N {
            return Err(PacketError::EncodeTooManyOffsets {
                count: self.count,
                expected: N,
            });
        }
        self.offsets[self.count] = -1i32;
        self.count += 1;
        Ok(())
    }

    #[inline]
    pub fn write_opt_string(&mut self, val: Option<&str>, field: &'static str) -> Result<(), PacketError> {
        match val {
            Some(s) => {
                self.record_offset()?;
                self.encoder.write_var_string(s, field)?;
                Ok(())
            }
            None => self.record_none(),
        }
    }

    #[inline]
    pub fn write_opt_bytes(&mut self, val: Option<&[u8]>) -> Result<(), PacketError> {
        match val {
            Some(data) => {
                self.record_offset()?;
                self.encoder.write_var_bytes(data)?;
                Ok(())
            }
            None => self.record_none(),
        }
    }

    #[inline]
    pub fn write_string(&mut self, val: &str, field: &'static str) -> Result<(), PacketError> {
        self.record_offset()?;
        self.encoder.write_var_string(val, field)?;
        Ok(())
    }

    #[inline]
    pub fn write_bytes(&mut self, val: &[u8]) -> Result<(), PacketError> {
        self.record_offset()?;
        self.encoder.write_var_bytes(val)?;
        Ok(())
    }

    #[inline]
    fn write_opt_primitive<F>(&mut self, val: Option<F>, write_fn: impl FnOnce(&mut PacketEncoder, F)) -> Result<(), PacketError> {
        match val {
            Some(v) => {
                self.record_offset()?;
                write_fn(self.encoder, v);
                Ok(())
            }
            None => self.record_none(),
        }
    }

    #[inline]
    pub fn write_opt_u8(&mut self, val: Option<u8>) -> Result<(), PacketError> {
        self.write_opt_primitive(val, |enc, v| enc.write_var_u8(v))
    }

    #[inline]
    pub fn write_opt_i16(&mut self, val: Option<i16>) -> Result<(), PacketError> {
        self.write_opt_primitive(val, |enc, v| enc.write_var_i16(v))
    }

    #[inline]
    pub fn write_opt_u16(&mut self, val: Option<u16>) -> Result<(), PacketError> {
        self.write_opt_primitive(val, |enc, v| enc.write_var_u16(v))
    }

    #[inline]
    pub fn write_opt_i32(&mut self, val: Option<i32>) -> Result<(), PacketError> {
        self.write_opt_primitive(val, |enc, v| enc.write_var_i32(v))
    }

    #[inline]
    pub fn write_opt_u32(&mut self, val: Option<u32>) -> Result<(), PacketError> {
        self.write_opt_primitive(val, |enc, v| enc.write_var_u32(v))
    }

    #[inline]
    pub fn write_opt_i64(&mut self, val: Option<i64>) -> Result<(), PacketError> {
        self.write_opt_primitive(val, |enc, v| enc.write_var_i64(v))
    }

    #[inline]
    pub fn write_opt_u64(&mut self, val: Option<u64>) -> Result<(), PacketError> {
        self.write_opt_primitive(val, |enc, v| enc.write_var_u64(v))
    }

    #[inline]
    pub fn write_opt_f32(&mut self, val: Option<f32>) -> Result<(), PacketError> {
        self.write_opt_primitive(val, |enc, v| enc.write_var_f32(v))
    }

    #[inline]
    pub fn write_opt_f64(&mut self, val: Option<f64>) -> Result<(), PacketError> {
        self.write_opt_primitive(val, |enc, v| enc.write_var_f64(v))
    }

    #[inline]
    pub fn write_opt_field<T: PacketField>(&mut self, val: Option<&T>) -> Result<(), PacketError> {
        match val {
            Some(v) => {
                self.record_offset()?;
                v.encode(&mut self.encoder.buf)
            }
            None => self.record_none(),
        }
    }

    #[inline]
    pub fn write_field<T: PacketField>(&mut self, val: &T) -> Result<(), PacketError> {
        self.record_offset()?;
        val.encode(&mut self.encoder.buf)
    }

    /// Finish and write offsets back to buffer
    #[inline]
    pub fn finish(self) -> Result<(), PacketError> {
        if self.count != N {
            return Err(PacketError::EncodeTooManyOffsets {
                count: self.count,
                expected: N,
            });
        }
        // Patch the offsets at the reserved position
        let mut patch_pos = self.pos as usize;
        for i in 0..self.count {
            let bytes = self.offsets[i].to_le_bytes();
            self.encoder.buf[patch_pos..patch_pos + 4].copy_from_slice(&bytes);
            patch_pos += 4;
        }
        Ok(())
    }
}

#[inline]
fn write_varint(buf: &mut Vec<u8>, mut value: usize) -> Result<(), PacketError> {
    const MAX_VARINT: usize = (1 << 28) - 1;
    if value > MAX_VARINT {
        return Err(PacketError::EncodeOverflow { field: "varint" });
    }

    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;

        if value == 0 {
            buf.push(byte);
            break;
        }

        buf.push(byte | 0x80);
    }

    Ok(())
}