use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_encoder::PacketEncoder;
use crate::server::core::network::packet::packet_error::PacketError;

#[derive(Debug)]
pub struct WorldLoadProgress {
    pub status: String,
    pub percent_complete: i32,
    pub percent_complete_subitem: i32,
}

impl Packet for WorldLoadProgress {
    fn packet_id() -> u32 {
        21
    }

    fn encode(&self, writer: &mut Vec<u8>) -> Result<(), PacketError> {
        let mut enc = PacketEncoder::new(writer);

        enc.write_null_bits(0);
        enc.write_i32(self.percent_complete);
        enc.write_i32(self.percent_complete_subitem);
        enc.write_var_string(&self.status, "status")?;

        Ok(())
    }

    fn decode(_buf: &[u8]) -> Result<Self, PacketError> {
        unimplemented!()
    }
}