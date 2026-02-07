use crate::packets::assets::update_type::UpdateType;
use crate::io::codecs::VarList;
use std::collections::HashMap;
use macros::{packet, packet_field};

#[packet(id = 46, max_size = 0x64000000, compressed)]
pub struct UpdateBlockSets {
    pub update_type: UpdateType,
    pub block_sets: HashMap<String, BlockSet>
}

#[packet_field]
pub struct BlockSet {
    pub name: Option<String>,
    pub blocks: VarList<i32, 4096000>
}