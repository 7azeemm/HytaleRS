use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_encoder::PacketEncoder;
use crate::server::core::network::packet::packet_error::PacketError;

#[derive(Debug)]
pub struct AuthGrant {
    pub auth_grant: String,
    pub server_identity_token: String
}

impl Packet for AuthGrant {
    fn packet_id() -> u32 {
        11
    }

    fn encode(&self, writer: &mut Vec<u8>) -> Result<(), PacketError> {
        let mut enc = PacketEncoder::new(writer);

        let null_bits = (1 << 0) | (1 << 1);
        enc.write_null_bits(null_bits);

        let mut offsets = enc.reserve_offsets::<2>()?;
        offsets.write_opt_string(Some(&self.auth_grant), "auth_grant")?;
        offsets.write_opt_string(Some(&self.server_identity_token), "server_identity_token")?;
        offsets.finish()?;

        Ok(())
    }

    fn decode(_buf: &[u8]) -> Result<Self, PacketError> {
        unimplemented!()
    }
}