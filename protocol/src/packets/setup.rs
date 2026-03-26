use crate::io::codecs::FixedString;
use crate::io::codecs::VarList;
use crate::io::codecs::VarString;
use macros::{packet, packet_field};
use std::sync::Arc;
use uuid::Uuid;
use crate::packets::message::FormattedMessage;

#[packet(id = 20, max_size = 0x64000000, compressed)]
pub struct WorldSettings {
    pub world_height: i32,
    pub required_assets: VarList<Arc<Asset>, 4096000>,
}

#[packet_field]
pub struct Asset {
    pub hash: FixedString<64>,
    pub name: VarString<512>,
}

#[packet(id = 223, max_size = 32769058)]
pub struct ServerInfo {
    pub max_players: i32,
    pub server_name: Option<String>,
    pub motd: Option<String>,
    pub fallback_server: Option<String>
}

#[packet(id = 21, max_size = 0x64000000)]
pub struct WorldLoadProgress {
    pub percent_complete: i32,
    pub percent_complete_subitem: i32,
    pub status: Option<FormattedMessage>,
}

#[packet(id = 22, max_size = 0)]
pub struct WorldLoadFinished {}

#[packet(id = 23, max_size = 0x64000000, compressed)]
pub struct RequestAssets {
    pub assets: VarList<Asset, 4096000>,
}

#[packet(id = 32, max_size = 4)]
pub struct ViewRadius {
    pub value: i32
}

#[packet(id = 33, max_size = 327680184)]
pub struct PlayerOptions {
    pub skin: Option<PlayerSkin>
}

#[packet_field]
pub struct PlayerSkin {
    pub body_characteristic: Option<String>,
    pub underwear: Option<String>,
    pub face: Option<String>,
    pub eyes: Option<String>,
    pub ears: Option<String>,
    pub mouth: Option<String>,
    pub facial_hair: Option<String>,
    pub haircut: Option<String>,
    pub eyebrows: Option<String>,
    pub pants: Option<String>,
    pub overpants: Option<String>,
    pub undertop: Option<String>,
    pub overtop: Option<String>,
    pub shoes: Option<String>,
    pub head_accessory: Option<String>,
    pub face_accessory: Option<String>,
    pub ear_accessory: Option<String>,
    pub skin_feature: Option<String>,
    pub gloves: Option<String>,
    pub cape: Option<String>,
}

//TODO: not here
#[packet(id = 104, max_size = 18)]
pub struct JoinWorld {
    pub clear_world: bool,
    pub fade_in_out: bool,
    pub world_uuid: Uuid
}