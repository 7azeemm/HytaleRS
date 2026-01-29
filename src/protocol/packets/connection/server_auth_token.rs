use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_encoder::PacketEncoder;
use crate::server::core::network::packet::packet_error::PacketError;

#[derive(Debug)]
pub struct ServerAuthToken {
    pub access_token: String,
    pub password_challenge: Vec<u8>
}

impl Packet for ServerAuthToken {
    fn packet_id() -> u32 {
        13
    }

    fn encode(&self, writer: &mut Vec<u8>) -> Result<(), PacketError> {
        let mut enc = PacketEncoder::new(writer);

        let null_bits = (1 << 0) | (1 << 1);
        enc.write_null_bits(null_bits);

        let mut offsets = enc.reserve_offsets::<2>()?;
        offsets.write_opt_string(Some(&self.access_token), "access_token")?;
        offsets.write_opt_bytes(Some(&self.password_challenge))?;
        offsets.finish()?;

        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        unimplemented!()
    }
}