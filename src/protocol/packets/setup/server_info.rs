use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_encoder::PacketEncoder;
use crate::server::core::network::packet::packet_error::PacketError;

#[derive(Debug)]
pub struct ServerInfo {
    pub server_name: String,
    pub motd: String,
    pub max_players: i32,
}

impl Packet for ServerInfo {
    fn packet_id() -> u32 {
        223
    }

    fn encode(&self, writer: &mut Vec<u8>) -> Result<(), PacketError> {
        let mut enc = PacketEncoder::new(writer);

        let null_bits = (1 << 0) | (1 << 1);
        enc.write_null_bits(null_bits);
        enc.write_i32(self.max_players);

        let mut offsets = enc.reserve_offsets::<2>()?;
        offsets.write_opt_string(Some(&self.server_name), "server_name")?;
        offsets.write_opt_string(Some(&self.motd), "motd")?;
        offsets.finish()?;

        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        unimplemented!()
    }
}