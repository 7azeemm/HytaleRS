use crate::io::codecs::PacketCodec;
use crate::io::errors::{PacketError, PacketResult};
use crate::io::packet::PacketLayout;
use crate::io::MAX_VARINT;
use std::mem::take;

pub struct Encoder {
    buf: Vec<u8>,
    scopes: Vec<Scope>,
}

struct NullBits {
    buf: Vec<u8>,
    index: usize,
    current_byte: u8,
    pos: usize,
}

struct Offsets {
    buf: Vec<u8>,
    pos: usize,
    var_pos: usize,
}

struct Scope {
    null_bits: Option<NullBits>,
    offsets: Option<Offsets>,
    in_opt_type: bool,
}

impl Scope {
    fn new(pos: usize, layout: &PacketLayout) -> Self {
        let null_bits = match layout.opt_field_count == 0 {
            true => None,
            false => Some(NullBits {
                buf: Vec::new(),
                index: 0,
                current_byte: 0,
                pos,
            })
        };

        let offsets = match layout.var_field_count <= 1 {
            true => None,
            false => Some(Offsets {
                buf: Vec::new(),
                pos: pos + layout.opt_field_count.div_ceil(8) + layout.fixed_block_size,
                var_pos: pos + layout.fixed_block_size,
            })
        };

        Self {
            null_bits,
            offsets,
            in_opt_type: false
        }
    }
}

impl Encoder {
    pub fn new(layout: &PacketLayout) -> Self {
        Self {
            buf: Vec::new(),
            scopes: vec![Scope::new(0, layout)],
        }
    }

    pub fn write<T: PacketCodec>(&mut self, value: &T) -> PacketResult<()> {
        if T::SIZE.is_none() {
            let buf_len = self.buf.len();
            if let Some(offsets) = self.scope().offsets.as_mut() {
                let offset = match value.has_value() {
                    true => (buf_len - offsets.var_pos) as i32,
                    false => -1,
                };
                offsets.buf.extend_from_slice(&offset.to_le_bytes());
            }
        }

        value.encode(self)
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_byte(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    pub fn write_zeros(&mut self, count: usize) {
        self.buf.resize(self.buf.len() + count, 0);
    }

    pub fn add_null_bit(&mut self, is_present: bool) -> bool {
        let scope = self.scope();
        scope.in_opt_type = match scope.in_opt_type {
            true => return false,
            false => true
        };

        let null_bits = scope.null_bits.as_mut().unwrap();
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

        true
    }

    pub fn leave_opt_type(&mut self) {
        self.scope().in_opt_type = false;
    }

    pub fn enter_field(&mut self, layout: &PacketLayout) {
        self.scopes.push(Scope::new(self.buf.len(), layout));
    }

    pub fn leave_field(&mut self) {
        let mut scope = self.scopes.pop().unwrap();

        if let Some(null_bits) = scope.null_bits.as_mut() {
            if null_bits.index > 0 {
                null_bits.buf.push(null_bits.current_byte);
            }

            let pos = null_bits.pos;
            self.buf.splice(pos..pos, take(&mut null_bits.buf));
        }

        if let Some(offsets) = scope.offsets {
            let pos = offsets.pos;
            self.buf.splice(pos..pos, offsets.buf);
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        let mut result = Vec::new();

        let mut scope = self.scopes.pop().unwrap();
        if let Some(null_bits) = scope.null_bits.as_mut() {
            if null_bits.index > 0 {
                null_bits.buf.push(null_bits.current_byte);
            }

            result.extend_from_slice(&null_bits.buf)
        }

        result.extend_from_slice(&self.buf);

        if let Some(offsets) = scope.offsets {
            let pos = offsets.pos;
            result.splice(pos..pos, offsets.buf);
        }

        result
    }

    fn scope(&mut self) -> &mut Scope {
        self.scopes.last_mut().unwrap()
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

            self.buf.push(byte);
            if value == 0 {
                break;
            }
        }

        Ok(())
    }
}
