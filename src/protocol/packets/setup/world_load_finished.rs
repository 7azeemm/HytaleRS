use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_error::PacketError;

#[derive(Debug)]
pub struct WorldLoadFinished {
}

impl Packet for WorldLoadFinished {
    fn packet_id() -> u32 {
        22
    }

    fn encode(&self, _writer: &mut Vec<u8>) -> Result<(), PacketError> {
        Ok(())
    }

    fn decode(_buf: &[u8]) -> Result<Self, PacketError> {
        unimplemented!()
    }
}