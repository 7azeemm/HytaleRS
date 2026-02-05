use std::sync::Arc;
use macros::packet_field;
use crate::io::codecs::{VarList, VarString};

packet! {
    id: 20,
    name: WorldSettings,
    compressed: true,
    max_size: 0x64000000,
    fixed { world_height: i32 },
    var { required_assets: VarList<Arc<Asset>, 4096000> }
}

#[packet_field]
pub struct Asset {
    pub hash: String,
    pub name: VarString<512>,
}

packet! {
    id: 223,
    name: ServerInfo,
    max_size: 32768023,
    fixed { max_players: i32 },
    var {
        server_name: Option<String>,
        motd: Option<String>
    }
}

packet! {
    id: 21,
    name: WorldLoadProgress,
    max_size: 16384014,
    fixed {
        percent_complete: i32,
        percent_complete_subitem: i32
    },
    var { status: String }
}

packet! {
    id: 22,
    name: WorldLoadFinished,
    max_size: 0
}

packet! {
    id: 23,
    name: RequestAssets,
    compressed: true,
    max_size: 0x64000000,
    var { assets: VarList<Asset, 4096000> }
}