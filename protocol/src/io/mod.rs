pub mod packet;
pub mod codecs;
pub mod errors;
pub mod encoder;
pub mod decoder;

pub const MAX_VARINT: usize = (1 << 28) - 1;