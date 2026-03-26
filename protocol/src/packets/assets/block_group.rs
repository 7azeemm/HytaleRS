use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 78, max_size = 0x64000000, compressed)]
pub struct UpdateBlockGroups {
    pub update_type: UpdateType,
    pub groups: HashMap<String, BlockGroupPacket>,
}

#[packet_field]
pub struct BlockGroupPacket {
    pub names: Vec<String>
}