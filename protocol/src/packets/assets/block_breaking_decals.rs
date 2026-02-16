use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 45, max_size = 0x64000000, compressed)]
pub struct UpdateBlockBreakingDecals {
    pub update_type: UpdateType,
    pub block_breaking_decals: HashMap<String, BlockBreakingDecalPacket>,
}

#[packet_field]
pub struct BlockBreakingDecalPacket {
    pub stage_textures: Vec<String>
}