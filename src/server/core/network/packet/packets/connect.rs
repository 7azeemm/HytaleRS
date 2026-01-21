use crate::server::core::network::packet::packet_codec::CodecField;
use HytaleRS::{Packet, PacketField};
use crate::server::core::network::packet::packets::host_address::HostAddress;

#[derive(Packet, Debug)]
#[packet_id(0)]
pub struct Connect {
    protocol_hash: String,
    client_type: ClientType,
    language: String,
    identity_token: String,
    uuid: String,
    username: String,
    referral_data: Vec<u8>,
    referral_source: HostAddress
}

#[derive(PacketField, Debug)]
pub enum ClientType {
    Game = 0,
    Editor = 1
}