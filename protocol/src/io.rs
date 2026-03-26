use std::sync::atomic::AtomicBool;

pub mod codecs;
pub mod decoder;
pub mod encoder;
pub mod errors;
pub mod packet;

pub const MAX_VARINT: usize = (1 << 28) - 1;
pub const DEBUG_PACKET_ID: u32 = 50;
pub static DEBUG: AtomicBool = AtomicBool::new(false);