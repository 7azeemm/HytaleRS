pub mod codecs;
pub mod decoder;
pub mod encoder;
pub mod errors;
pub mod packet;

pub const MAX_VARINT: usize = (1 << 28) - 1;
