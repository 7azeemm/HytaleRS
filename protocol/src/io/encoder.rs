use crate::io::codecs::PacketCodec;
use crate::io::MAX_VARINT;
use crate::io::errors::{PacketError, PacketResult};

pub struct Encoder {
    null_bits_buf: Vec<u8>,
    fixed_buf: Vec<u8>,
    offsets_buf: Vec<u8>,
    var_buf: Vec<u8>,

    current_null_byte: u8,
    null_bit_index: usize,  // 0-7 within current_null_byte
    pub in_fixed_block: bool,
}

impl Encoder {
    pub fn new() -> Self {
        Encoder {
            null_bits_buf: Vec::new(),
            fixed_buf: Vec::new(),
            offsets_buf: Vec::new(),
            var_buf: Vec::new(),
            current_null_byte: 0,
            null_bit_index: 0,
            in_fixed_block: true,
        }
    }

    pub fn write_fixed<T: PacketCodec>(&mut self, value: &T, field: &'static str) -> PacketResult<()> {
        assert!(T::SIZE.is_some(), "`{field}` requires fixed size");
        value.encode(self)
    }

    pub fn write_var<T: PacketCodec>(&mut self, value: &T) -> PacketResult<()> {
        self.add_offset(self.var_buf.len() as i32);
        value.encode(self)
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        if self.in_fixed_block {
            self.fixed_buf.extend_from_slice(bytes);
        } else {
            self.var_buf.extend_from_slice(bytes);
        }
    }

    pub fn write_byte(&mut self, byte: u8) {
        if self.in_fixed_block {
            self.fixed_buf.push(byte);
        } else {
            self.var_buf.push(byte);
        }
    }

    pub fn write_zeros(&mut self, count: usize) {
        self.fixed_buf.resize(self.fixed_buf.len() + count, 0);
    }

    pub fn enter_var_block(&mut self) {
        assert!(self.in_fixed_block, "enter_var_block called when already in variable block");
        self.in_fixed_block = false;
    }
    
    pub fn write_varint(&mut self, mut value: usize) -> PacketResult<()> {
        if value > MAX_VARINT {
            return Err(PacketError::EncodeError("varint overflow".into()));
        }

        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;

            if value != 0 {
                byte |= 0x80;
            }

            self.write_byte(byte);
            if value == 0 {
                break;
            }
        }

        Ok(())
    }

    pub fn finish(mut self) -> Vec<u8> {
        // Flush any pending null byte
        if self.null_bit_index > 0 {
            self.null_bits_buf.push(self.current_null_byte);
        }

        let mut result = Vec::new();
        result.extend_from_slice(&self.null_bits_buf);
        result.extend_from_slice(&self.fixed_buf);
        result.extend_from_slice(&self.offsets_buf);
        result.extend_from_slice(&self.var_buf);
        result
    }

    pub fn add_null_bit(&mut self, is_present: bool) {
        if is_present {
            self.current_null_byte |= 1 << self.null_bit_index;
        }

        self.null_bit_index += 1;

        // When we reach 8 bits, flush to buffer
        if self.null_bit_index == 8 {
            self.null_bits_buf.push(self.current_null_byte);
            self.current_null_byte = 0;
            self.null_bit_index = 0;
        }
    }

    pub fn edit_last_offset(&mut self, new_offset: i32) -> PacketResult<()> {
        assert!(self.offsets_buf.len() >= 4, "edit_last_offset called with no offsets written");

        let start = self.offsets_buf.len() - 4;
        self.offsets_buf[start..start + 4].copy_from_slice(&new_offset.to_le_bytes());
        Ok(())
    }

    fn add_offset(&mut self, offset: i32) {
        self.offsets_buf.extend_from_slice(&offset.to_le_bytes());
    }
}
