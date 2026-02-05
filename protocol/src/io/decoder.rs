use crate::io::codecs::PacketCodec;
use crate::io::packet::PacketLayout;
use crate::io::errors::{PacketError, PacketResult};

pub struct Decoder<'a> {
    null_bits_buf: &'a [u8],
    fixed_buf: &'a [u8],
    offsets_buf: &'a [u8],
    var_buf: &'a [u8],

    fixed_pos: usize,
    var_pos: usize,
    offset_pos: usize,
    null_bit_index: usize,
    in_fixed_block: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8], layout: &PacketLayout) -> PacketResult<Self> {
        let total_size = data.len();

        let null_bits_size = (layout.optional_field_count + 7) / 8;
        let fixed_size = layout.fixed_block_size;
        let offsets_size = layout.var_field_count * 4;

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

        let offsets_buf = &data[pos..pos + offsets_size];
        pos += offsets_size;

        let var_buf = &data[pos..];

        Ok(Decoder {
            null_bits_buf,
            fixed_buf,
            offsets_buf,
            var_buf,
            fixed_pos: 0,
            var_pos: 0,
            offset_pos: 0,
            null_bit_index: 0,
            in_fixed_block: true,
        })
    }

    pub fn read_fixed<T: PacketCodec>(&mut self, field: &'static str) -> PacketResult<T> {
        assert!(T::SIZE.is_some(), "`{field}` requires fixed size");
        T::decode(self)
    }

    pub fn read_var<T: PacketCodec>(&mut self, field: &'static str) -> PacketResult<T> {
        let offset = self.read_offset(field)?;
        self.seek_var(offset, field)?;
        T::decode(self)
    }

    pub fn read_bytes(&mut self, count: usize) -> PacketResult<&'a [u8]> {
        let buf = match self.in_fixed_block {
            true => self.fixed_buf,
            false => self.var_buf,
        };
        let pos = match self.in_fixed_block {
            true => self.fixed_pos,
            false => self.var_pos,
        };

        if pos + count > buf.len() {
            return Err(PacketError::DecodeError("EOF while reading bytes".into()));
        }

        let bytes = &buf[pos..pos + count];

        match self.in_fixed_block {
            true => self.fixed_pos += count,
            false => self.var_pos += count,
        }

        Ok(bytes)
    }

    pub fn read_byte(&mut self) -> PacketResult<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
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

    pub fn read_null_bit(&mut self) -> bool {
        let byte_index = self.null_bit_index / 8;
        let bit_index = self.null_bit_index % 8;

        self.null_bit_index += 1;

        if byte_index >= self.null_bits_buf.len() {
            return false;
        }

        let byte = self.null_bits_buf[byte_index];
        (byte & (1 << bit_index)) != 0
    }

    fn read_offset(&mut self, field: &'static str) -> PacketResult<i32> {
        if self.offset_pos + 4 > self.offsets_buf.len() {
            return Err(PacketError::DecodeError(
                format!("Offset out of bounds while reading field '{}'", field)
            ));
        }

        let offset_bytes = &self.offsets_buf[self.offset_pos..self.offset_pos + 4];
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
