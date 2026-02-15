use crate::io::codecs::VarList;
use crate::packets::assets::update_type::UpdateType;
use macros::{packet, packet_field};
use std::collections::HashMap;

#[packet(id = 46, max_size = 0x64000000, compressed)]
pub struct UpdateBlockSets {
    pub update_type: UpdateType,
    pub block_sets: HashMap<String, BlockSetPacket>,
}

#[packet_field]
pub struct BlockSetPacket {
    pub name: Option<String>,
    pub blocks: VarList<i32, 4096000>,
}
