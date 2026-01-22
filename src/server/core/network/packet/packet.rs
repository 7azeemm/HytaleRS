use std::fmt::Debug;
use std::io::Write;
use crate::server::core::network::packet::packets::connect::PacketDecoder;
use super::packet_codec::CodecError;

pub trait Packet: Send + Sync + Sized + Debug {
    fn packet_id(&self) -> u32;
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()>;
    fn decode(buf: &[u8]) -> Result<Self, CodecError>;
}

pub trait PacketField: Send + Sync + Sized + Debug {
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()>;
    fn decode(dec: &mut PacketDecoder, offset: i32) -> Result<Self, CodecError>;
}