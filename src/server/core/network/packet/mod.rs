pub mod packet;
pub mod packet_error;
pub mod packet_handler;
pub mod packet_decoder;
pub mod packet_encoder;

pub const MAX_PACKET_SIZE: u32 = 262_144; // 256 KB
pub const MAX_STRING_LEN: usize = 65536; // 64 KB
