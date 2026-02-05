use crate::io::codecs::PacketCodec;
use crate::io::MAX_VARINT;
use crate::io::errors::{PacketError, PacketResult};
use crate::io::packet::PacketLayout;

pub struct Encoder {
    fixed_buf: Vec<u8>,
    var_buf: Vec<u8>,

    null_bits: Vec<NullBits>,
    current_null_bits_index: usize,
    offsets_buf: Option<Vec<u8>>,

    in_fixed_block: bool,
}

struct NullBits {
    buf: Vec<u8>,
    index: usize,
    current_byte: u8
}

impl Encoder {
    pub fn new(layout: &PacketLayout) -> Self {
        let offsets_buf = if layout.var_field_count > 1 { Some(Vec::new()) } else { None };
        let null_bits = NullBits{
            buf: Vec::new(),
            index: 0,
            current_byte: 0
        };

        Encoder {
            fixed_buf: Vec::new(),
            var_buf: Vec::new(),
            null_bits: vec![null_bits],
            current_null_bits_index: 0,
            offsets_buf,
            in_fixed_block: true,
        }
    }

    pub fn write_fixed<T: PacketCodec>(&mut self, value: &T, field: &'static str) -> PacketResult<()> {
        assert!(T::SIZE.is_some(), "`{field}` requires fixed size");
        value.encode(self)
    }

    pub fn write_var<T: PacketCodec>(&mut self, value: &T) -> PacketResult<()> {
        // workaround to suppress false IDE warning
        let is_optional: bool = T::IS_OPTIONAL;
        if is_optional {
            self.add_null_bit(value.has_value())
        }
        
        if let Some(offsets_buf) = self.offsets_buf.as_mut() {
            let offset = if value.has_value() { self.var_buf.len() as i32 } else { -1 };
            offsets_buf.extend_from_slice(&offset.to_le_bytes());
        }

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

    pub fn enter_field(&mut self) {
        self.current_null_bits_index = self.null_bits.len();
        self.null_bits.push(NullBits {
            buf: Vec::new(),
            index: 0,
            current_byte: 0,
        })
    }

    pub fn leave_field(&mut self) {
        let null_bits = self.null_bits.pop().unwrap();
        self.current_null_bits_index = self.null_bits.len() - 1;
        self.write_bytes(&null_bits.buf);
    }

    pub fn finish(mut self) -> Vec<u8> {
        // Flush any pending null byte
        let null_bits = &mut self.null_bits[self.current_null_bits_index];
        if null_bits.index > 0 {
            null_bits.buf.push(null_bits.current_byte);
        }

        let mut result = Vec::new();
        result.extend_from_slice(&null_bits.buf);
        result.extend_from_slice(&self.fixed_buf);
        if let Some(offsets_buf) = self.offsets_buf {
            result.extend_from_slice(&offsets_buf);
        }
        result.extend_from_slice(&self.var_buf);
        result
    }

    pub fn add_null_bit(&mut self, is_present: bool) {
        let null_bits = &mut self.null_bits[self.current_null_bits_index];
        if is_present {
            null_bits.current_byte |= 1 << null_bits.index;
        }

        null_bits.index += 1;

        // When we reach 8 bits, flush to buffer
        if null_bits.index == 8 {
            null_bits.buf.push(null_bits.current_byte);
            null_bits.current_byte = 0;
            null_bits.index = 0;
        }
    }
}
