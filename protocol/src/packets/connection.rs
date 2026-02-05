use uuid::Uuid;
use macros::{packet_enum, packet_field};
use crate::io::codecs::{FixedAsciiString, VarList, VarString};
use crate::packet;

packet! {
    id: 0,
    name: Connect,
    max_size: 38013,
    fixed {
        protocol_crc: i32,
        protocol_build_number: i32,
        client_version: FixedAsciiString<20>,
        client_type: ClientType,
        uuid: Uuid
    },
    var {
        username: VarString<16>,
        identity_token: Option<VarString<8192>>,
        language: VarString<16>,
        referral_data: VarList<u8, 8192>,
        referral_source: Option<HostAddress>,
    }
}

#[packet_enum]
pub enum ClientType {
    Game,
    Editor
}

#[packet_field]
pub struct HostAddress {
    pub port: i16,
    pub host: VarString<256>
}

packet! {
    id: 1,
    name: Disconnect,
    max_size: 16384007,
    fixed { cause: DisconnectCause },
    var { reason: Option<String> }
}

#[packet_enum]
pub enum DisconnectCause {
    Disconnect,
    Crash
}

packet! {
    id: 11,
    name: AuthGrant,
    max_size: 49171,
    var {
        auth_grant: Option<VarString<4096>>,
        server_identity_token: Option<VarString<8192>>
    }
}

packet! {
    id: 12,
    name: AuthToken,
    max_size: 49171,
    var {
        access_token: Option<VarString<8192>>,
        server_auth_grant: Option<VarString<4096>>
    }
}

packet! {
    id: 13,
    name: ServerAuthToken,
    max_size: 32851,
    var {
        access_token: Option<VarString<8192>>,
        password_challenge: VarList<u8, 64>
    }
}