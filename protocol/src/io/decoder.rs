use crate::io::codecs::PacketCodec;
use crate::io::errors::{PacketError, PacketResult};
use crate::io::packet::PacketLayout;

pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    scopes: Vec<Scope<'a>>,
}

struct NullBits<'a> {
    buf: &'a [u8],
    index: usize,
}

struct Offsets<'a> {
    buf: Option<&'a [u8]>,
    pos: usize,
    start_pos: usize,
    size: usize,
}

impl<'a> Offsets<'a> {
    fn read_offset(&mut self, field: &'static str) -> PacketResult<i32> {
        let buf = self.buf.as_mut().unwrap();
        if buf.len() < 4 {
            return Err(PacketError::DecodeError(format!(
                "Offset out of bounds while reading field '{}'",
                field
            )));
        }

        let pos = self.pos;
        let offset_bytes = &buf[pos..pos + 4];
        self.pos += 4;

        let offset = i32::from_le_bytes(offset_bytes.try_into().unwrap());
        if offset == -1 {
            return Ok(-1);
        }

        Ok((self.start_pos + self.size) as i32 + offset)
    }
}

struct Scope<'a> {
    null_bits: Option<NullBits<'a>>,
    offsets: Option<Offsets<'a>>,
}

impl<'a> Scope<'a> {
    fn new(dec: &mut Decoder<'a>, pos: usize, layout: &PacketLayout) -> Self {
        let null_bits_size = layout.var_field_count.div_ceil(8);

        let null_bits = if null_bits_size == 0 {
            None
        } else {
            dec.pos += null_bits_size;
            Some(NullBits {
                buf: &dec.buf[pos..pos + null_bits_size],
                index: 0,
            })
        };

        let offsets = if layout.var_field_count <= 1 {
            None
        } else {
            Some(Offsets {
                buf: None,
                pos: 0,
                start_pos: pos + null_bits_size + layout.fixed_block_size,
                size: layout.var_field_count * 4,
            })
        };

        Self { null_bits, offsets }
    }
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8], layout: &PacketLayout) -> PacketResult<Self> {
        let null_bits_size = layout.var_field_count.div_ceil(8);
        let offsets_size = if layout.var_field_count > 1 {
            layout.var_field_count * 4
        } else {
            0
        };

        let min_size = null_bits_size + layout.fixed_block_size + offsets_size;
        if buf.len() < min_size {
            return Err(PacketError::Error(format!(
                "Packet too small: expected at least {}, got {}",
                min_size,
                buf.len()
            )));
        }

        let mut dec = Decoder {
            scopes: vec![],
            pos: 0,
            buf,
        };

        let scope = Scope::new(&mut dec, 0, layout);
        dec.scopes.push(scope);

        Ok(dec)
    }

    pub fn read<T: PacketCodec>(&mut self, field: &'static str) -> PacketResult<T> {
        if T::SIZE.is_none() {
            let mut entering_var_block = None;
            let current_pos = self.pos;
            if let Some(offsets) = self.scope().offsets.as_mut() {
                if offsets.buf.is_some() {
                    let new_pos = offsets.read_offset(field)?;
                    self.move_to(new_pos, field)?;
                } else if current_pos == offsets.start_pos {
                    entering_var_block = Some(offsets.size);
                }
            }

            if let Some(offsets_size) = entering_var_block {
                let buf = &self.buf[self.pos + 4..self.pos + offsets_size];
                self.pos += offsets_size;
                self.scope().offsets.as_mut().unwrap().buf = Some(buf);
            }
        }

        T::decode(self)
    }

    pub fn read_bytes(&mut self, count: usize) -> PacketResult<&'a [u8]> {
        let pos = self.pos;
        if pos + count > self.buf.len() {
            return Err(PacketError::DecodeError("EOF while reading bytes".into()));
        }

        let bytes = &self.buf[pos..pos + count];
        self.pos += count;

        Ok(bytes)
    }

    pub fn read_byte(&mut self) -> PacketResult<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    pub fn read_zeros(&mut self, count: usize) -> PacketResult<()> {
        self.pos += count;
        if self.pos > self.buf.len() {
            return Err(PacketError::DecodeError("EOF while reading zero bytes".into()));
        }
        Ok(())
    }

    pub fn enter_field(&mut self, layout: &PacketLayout) {
        let scope = Scope::new(self, self.pos, layout);
        self.scopes.push(scope);
    }

    pub fn leave_field(&mut self) {
        self.scopes.pop().unwrap();
    }

    pub fn read_null_bit(&mut self) -> bool {
        let null_bits = self.scope().null_bits.as_mut().unwrap();
        let byte_index = null_bits.index / 8;
        let bit_index = null_bits.index % 8;

        null_bits.index += 1;

        if byte_index >= null_bits.buf.len() {
            return false;
        }

        let byte = null_bits.buf[byte_index];
        (byte & (1 << bit_index)) != 0
    }

    fn move_to(&mut self, new_pos: i32, field: &'static str) -> PacketResult<()> {
        if new_pos == -1 {
            return Ok(());
        }
        let new_pos = new_pos as usize;

        if new_pos >= self.buf.len() {
            return Err(PacketError::DecodeError(format!(
                "Offset {} out of bounds for variable field '{}'",
                new_pos, field
            )));
        }

        self.pos = new_pos;
        Ok(())
    }

    fn scope(&mut self) -> &mut Scope<'a> {
        self.scopes.last_mut().unwrap()
    }

    pub fn read_varint(&mut self) -> PacketResult<usize> {
        let mut value = 0usize;
        let mut shift = 0u32;

        loop {
            if shift >= 35 {
                return Err(PacketError::DecodeError("varint is too long".into()));
            }

            let byte = self.read_byte()?;
            value |= ((byte & 0x7F) as usize) << shift;

            if byte & 0x80 == 0 {
                return Ok(value);
            }

            shift += 7;
        }
    }
}
