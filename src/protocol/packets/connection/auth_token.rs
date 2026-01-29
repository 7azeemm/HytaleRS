use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_decoder::PacketDecoder;
use crate::server::core::network::packet::packet_error::PacketError;

#[derive(Debug)]
pub struct AuthToken {
    pub access_token: Option<String>,
    pub server_auth_grant: Option<String>
}

impl Packet for AuthToken {
    fn packet_id() -> u32 {
        12
    }

    fn encode(&self, _writer: &mut Vec<u8>) -> Result<(), PacketError> {
        unimplemented!()
    }

    fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        let mut dec = PacketDecoder::new(buf);

        let nulls = dec.read_null_bits()?;
        let offsets = dec.read_offsets::<2>()?;
        let access_token = dec.read_opt_string(nulls, 0, offsets[0], "access_token")?;
        let server_auth_grant = dec.read_opt_string(nulls, 1, offsets[1], "server_auth_grant")?;

        Ok(Self { access_token, server_auth_grant })
    }
}