use std::fmt::Debug;
use std::io::Write;
use crate::server::core::network::packet::packet_decoder::PacketDecoder;
use super::packet_error::PacketError;

pub trait Packet: Send + Sync + Sized + Debug {
    fn packet_id() -> u32;
    fn encode(&self, writer: &mut Vec<u8>) -> Result<(), PacketError>;
    fn decode(buf: &[u8]) -> Result<Self, PacketError>;
}

pub trait PacketField: Send + Sync + Sized + Debug {
    fn encode(&self, writer: &mut dyn Write) -> Result<(), PacketError>;
    fn decode(dec: &mut PacketDecoder, offset: i32) -> Result<Self, PacketError>;
}