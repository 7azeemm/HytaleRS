use crate::server::core::network::packet::packet::{Packet, PacketField};
use crate::server::core::network::packet::packet_error::PacketError;
use std::io::Write;
use num_enum::TryFromPrimitive;
use uuid::Uuid;
use crate::server::core::network::packet::packet_decoder::PacketDecoder;

#[derive(Debug)]
pub struct Connect {
    pub protocol_crc: i32,
    pub protocol_build_number: i32,
    pub client_version: String,
    pub client_type: ClientType,
    pub uuid: Uuid,
    pub username: String,
    pub identity_token: Option<String>,
    pub language: String,
    pub referral_data: Option<Vec<u8>>,
    pub referral_source: Option<HostAddress>,
}

#[derive(Debug, TryFromPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum ClientType {
    Game,
    Editor
}

#[derive(Debug, Clone)]
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
        let protocol_crc = dec.read_i32("protocol_crc")?;
        let protocol_build_number = dec.read_i32("protocol_build_number")?;
        let client_version = dec.read_fixed_string(20, "client_version")?;
        let client_type = ClientType::try_from(dec.read_u8("client_type")?)?;
        let uuid = dec.read_uuid("uuid")?;

        let offsets = dec.read_offsets::<5>()?;
        let username = dec.read_var_string(offsets[0], "username")?;
        let identity_token = dec.read_opt_string(nulls, 0, offsets[1], "identity_token")?;
        let language = dec.read_var_string(offsets[2], "language")?;
        let referral_data = dec.read_opt_bytes(nulls, 1, offsets[3], "referral_data")?;
        let referral_source = dec.read_opt_field::<HostAddress>(nulls, 2, offsets[4])?;

        Ok(Self {
            protocol_crc,
            protocol_build_number,
            client_version,
            client_type,
            uuid,
            username,
            identity_token,
            language,
            referral_data,
            referral_source,
        })
    }
}

impl PacketField for HostAddress {
    fn encode(&self, _writer: &mut dyn Write) -> Result<(), PacketError> {
        unimplemented!()
    }

    fn decode(dec: &mut PacketDecoder, offset: i32) -> Result<Self, PacketError> {
        let port = dec.read_var_i16(offset, "port")?;
        let host = dec.read_var_string(offset + 2, "host")?;
        Ok(Self { host, port })
    }
}
