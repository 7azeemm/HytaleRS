use crate::server::core::network::packet::packet::{Packet, PacketField};
use crate::server::core::network::packet::packet_error::PacketError;
use std::io::Write;
use num_enum::TryFromPrimitive;
use uuid::Uuid;
use crate::server::core::network::packet::packet_decoder::PacketDecoder;

#[derive(Debug)]
pub struct Connect {
    pub protocol_hash: String,
    pub client_type: ClientType,
    pub uuid: Uuid,
    pub language: Option<String>,
    pub identity_token: Option<String>,
    pub username: String,
    pub referral_data: Option<Vec<u8>>,
    pub referral_source: Option<HostAddress>,
}

#[derive(Debug, TryFromPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum ClientType {
    Game,
    Editor
}

#[derive(Debug)]
pub struct HostAddress {
    pub host: String,
    pub port: i16
}

impl Packet for Connect {
    fn packet_id() -> u32 {
        0x00
    }

    fn encode(&self, _writer: &mut Vec<u8>) -> Result<(), PacketError> {
        unimplemented!()
    }

    fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        let mut dec = PacketDecoder::new(&buf);

        let nulls = dec.read_null_bits()?;
        let protocol_hash = dec.read_fixed_string(64, "protocol_hash")?;
        let client_type = ClientType::try_from(dec.read_u8("client_type")?)?;
        let uuid = dec.read_uuid("uuid")?;

        let offsets = dec.read_offsets::<5>()?;

        let language = dec.read_opt_string(nulls, 0, offsets[0], "language")?;
        let identity_token = dec.read_opt_string(nulls, 1, offsets[1], "identity_token")?;
        let username = dec.read_var_string(offsets[2], "username")?;
        let referral_data = dec.read_opt_bytes(nulls, 2, offsets[3], "referral_data")?;
        let referral_source = dec.read_opt_field::<HostAddress>(nulls, 3, offsets[4])?;

        Ok(Self {
            protocol_hash,
            client_type,
            uuid,
            language,
            identity_token,
            username,
            referral_data,
            referral_source,
        })
    }
}

impl PacketField for HostAddress {
    fn encode(&self, _writer: &mut dyn Write) -> std::io::Result<()> {
        unimplemented!()
    }

    fn decode(dec: &mut PacketDecoder, offset: i32) -> Result<Self, PacketError> {
        let port = dec.read_var_i16(offset, "port")?;
        let host = dec.read_var_string(offset + 2, "host")?;
        Ok(Self { host, port })
    }
}