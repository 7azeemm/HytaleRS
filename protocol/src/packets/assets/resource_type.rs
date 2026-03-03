use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 59, max_size = 0x64000000, compressed)]
pub struct UpdateResourceTypes {
    pub update_type: UpdateType,
    pub resource_types: HashMap<String, ResourceTypePacket>,
}

#[packet_field]
pub struct ResourceTypePacket {
    pub id: Option<String>,
    pub icon: Option<String>
}