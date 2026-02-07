use crate::io::codecs::VarString;
use crate::io::codecs::FixedString;
use crate::io::codecs::VarList;
use std::sync::Arc;
use macros::{packet, packet_field};

#[packet(id = 20, max_size = 0x64000000, compressed)]
pub struct WorldSettings {
    pub world_height: i32,
    pub required_assets: VarList<Arc<Asset>, 4096000>
}

#[packet_field]
pub struct Asset {
    pub hash: FixedString<64>,
    pub name: VarString<512>,
}

#[packet(id = 223, max_size = 32768023)]
pub struct ServerInfo {
    pub max_players: i32,
    pub server_name: Option<String>,
    pub motd: Option<String>
}

#[packet(id = 21, max_size = 16384014)]
pub struct WorldLoadProgress {
    pub percent_complete: i32,
    pub percent_complete_subitem: i32,
    pub status: String
}

#[packet(id = 22, max_size = 0)]
pub struct WorldLoadFinished {
}

#[packet(id = 23, max_size = 0x64000000, compressed)]
pub struct RequestAssets {
    pub assets: VarList<Asset, 4096000>
}