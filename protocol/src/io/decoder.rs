use crate::io::codecs::PacketCodec;
use crate::io::packet::PacketLayout;
use crate::io::errors::{PacketError, PacketResult};

pub struct Decoder<'a> {
    fixed_buf: &'a [u8],
    var_buf: &'a [u8],

    null_bits: Vec<NullBits<'a>>,
    current_null_bits_index: usize,
    offsets_buf: Option<&'a [u8]>,

    fixed_pos: usize,
    var_pos: usize,
    offset_pos: usize,
    in_fixed_block: bool,
}

struct NullBits<'a> {
    buf: &'a [u8],
    index: usize,
    current_value: bool
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8], layout: &PacketLayout) -> PacketResult<Self> {
        let total_size = data.len();

        let has_offsets = layout.var_field_count > 1;
        let null_bits_size = (layout.optional_field_count + 7) / 8;
        let fixed_size = layout.fixed_block_size;
        let offsets_size = if has_offsets { layout.var_field_count * 4 } else { 0 };

        let expected_min_size = null_bits_size + fixed_size + offsets_size;
        if total_size < expected_min_size {
            return Err(PacketError::Error(
                format!("Packet too small: expected at least {}, got {}", expected_min_size, total_size)
            ));
        }

        let mut pos = 0;

        let null_bits_buf = &data[pos..pos + null_bits_size];
        pos += null_bits_size;

        let fixed_buf = &data[pos..pos + fixed_size];
        pos += fixed_size;

        let offsets_buf = if has_offsets {
            let buf = &data[pos..pos + offsets_size];
            pos += offsets_size;
            Some(buf)
        } else { None };

        let var_buf = &data[pos..];

        let null_bits = NullBits {
            buf: null_bits_buf,
            index: 0,
            current_value: false
        };

        Ok(Decoder {
            fixed_buf,
            var_buf,
            null_bits: vec![null_bits],
            current_null_bits_index: 0,
            offsets_buf,
            fixed_pos: 0,
            var_pos: 0,
            offset_pos: 0,
            in_fixed_block: true,
        })
    }

    pub fn read_fixed<T: PacketCodec>(&mut self, field: &'static str) -> PacketResult<T> {
        assert!(T::SIZE.is_some(), "`{field}` requires fixed size");

        // workaround to suppress false IDE warning
        let is_optional: bool = T::IS_OPTIONAL;
        if is_optional {
            let _ = self.read_null_bit();
        }

        T::decode(self)
    }

    pub fn read_var<T: PacketCodec>(&mut self, field: &'static str) -> PacketResult<T> {
        // workaround to suppress false IDE warning
        let is_optional: bool = T::IS_OPTIONAL;
        if !is_optional || self.read_null_bit() {
            if let Some(offset_buf) = self.offsets_buf {
                let offset = self.read_offset(offset_buf, field)?;
                self.seek_var(offset, field)?;
            }
        }

        T::decode(self)
    }

    pub fn read_bytes(&mut self, count: usize) -> PacketResult<&'a [u8]> {
        let buf = self.buf();
        let pos = self.pos();

        if pos + count > buf.len() {
            return Err(PacketError::DecodeError("EOF while reading bytes".into()));
        }

        let bytes = &buf[pos..pos + count];
        self.inc_pos(count);

        Ok(bytes)
    }

    pub fn read_byte(&mut self) -> PacketResult<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub fn buf(&self) -> &'a [u8] {
        match self.in_fixed_block {
            true => self.fixed_buf,
            false => self.var_buf,
        }
    }

    pub fn pos(&self) -> usize {
        match self.in_fixed_block {
            true => self.fixed_pos,
            false => self.var_pos,
        }
    }

    pub fn inc_pos(&mut self, count: usize) {
        match self.in_fixed_block {
            true => self.fixed_pos += count,
            false => self.var_pos += count,
        }
    }

    pub fn current_null_value(&self) -> bool {
        self.null_bits[self.current_null_bits_index].current_value
    }

    pub fn enter_var_block(&mut self) {
        assert!(self.in_fixed_block, "enter_var_block called when already in variable block");
        self.in_fixed_block = false;
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

    pub fn enter_field(&mut self, optional_field_count: usize) -> PacketResult<()> {
        let null_bits_size = (optional_field_count + 7) / 8;
        let buf = self.read_bytes(null_bits_size)?;

        self.current_null_bits_index = self.null_bits.len();
        self.null_bits.push(NullBits {
            buf,
            index: 0,
            current_value: false
        });

        Ok(())
    }

    pub fn leave_field(&mut self) {
        self.null_bits.pop();
        self.current_null_bits_index = self.null_bits.len() - 1;
    }

    pub fn read_null_bit(&mut self) -> bool {
        let null_bits = &mut self.null_bits[self.current_null_bits_index];
        let byte_index = null_bits.index / 8;
        let bit_index = null_bits.index % 8;

        null_bits.index += 1;

        if byte_index >= null_bits.buf.len() {
            return false;
        }

        let byte = null_bits.buf[byte_index];
        null_bits.current_value = (byte & (1 << bit_index)) != 0;
        null_bits.current_value
    }

    fn read_offset(&mut self, buf: &'a [u8], field: &'static str) -> PacketResult<i32> {
        if self.offset_pos + 4 > buf.len() {
            return Err(PacketError::DecodeError(
                format!("Offset out of bounds while reading field '{}'", field)
            ));
        }

        let offset_bytes = &buf[self.offset_pos..self.offset_pos + 4];
        self.offset_pos += 4;

        let bytes: [u8; 4] = offset_bytes.try_into().unwrap();
        Ok(i32::from_le_bytes(bytes))
    }

    fn seek_var(&mut self, offset: i32, field: &'static str) -> PacketResult<()> {
        if offset == -1 { return Ok(()) }
        let offset = offset as usize;

        if offset >= self.var_buf.len() {
            return Err(PacketError::DecodeError(
                format!("Offset {} out of bounds for variable field '{}'", offset, field)
            ));
        }
        self.var_pos = offset;
        Ok(())
    }
}
