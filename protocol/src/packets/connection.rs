use crate::io::codecs::{FixedString, VarList, VarString};
use macros::{packet, packet_enum, packet_field};
use uuid::Uuid;
use crate::packets::message::FormattedMessage;

#[packet(id = 0, max_size = 38013)]
pub struct Connect {
    pub protocol_crc: i32,
    pub protocol_build_number: i32,
    pub client_version: FixedString<20>,
    pub client_type: ClientType,
    pub uuid: Uuid,
    pub username: VarString<16>,
    pub identity_token: Option<VarString<8192>>,
    pub language: VarString<16>,
    pub referral_data: VarList<u8, 4096>,
    pub referral_source: Option<HostAddress>,
}

#[packet_enum]
pub enum ClientType {
    Game,
    Editor,
}

#[packet_field]
pub struct HostAddress {
    pub port: i16,
    pub host: VarString<256>,
}

#[packet(id = 1, max_size = 2)]
pub struct ClientDisconnect {
    pub reason: ClientDisconnectReason,
    pub disconnect_type: DisconnectType,
}

#[packet_enum]
pub enum ClientDisconnectReason {
    PlayerLeave,
    PlayerAbort,
    UserLeave,
    Crash
}

#[packet_enum]
pub enum DisconnectType {
    Disconnect,
    Crash,
}

#[packet(id = 2, max_size = 0x64000000)]
pub struct ServerDisconnect {
    pub disconnect_type: DisconnectType,
    pub reason: Option<FormattedMessage>,
}

#[packet(id = 11, max_size = 49171)]
pub struct AuthGrant {
    pub auth_grant: Option<VarString<4096>>,
    pub server_identity_token: Option<VarString<8192>>,
}

#[packet(id = 12, max_size = 49171)]
pub struct AuthToken {
    pub access_token: Option<VarString<8192>>,
    pub server_auth_grant: Option<VarString<4096>>,
}

#[packet(id = 13, max_size = 32851)]
pub struct ServerAuthToken {
    pub access_token: Option<VarString<8192>>,
    pub password_challenge: VarList<u8, 64>,
}
