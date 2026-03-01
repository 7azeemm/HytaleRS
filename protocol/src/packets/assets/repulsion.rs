use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 75, max_size = 65536011, compressed)]
pub struct UpdateRepulsionConfigs {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub repulsion_configs: HashMap<i32, RepulsionConfigPacket>,
}

#[packet_field]
pub struct RepulsionConfigPacket {
    pub radius: f32,
    pub min_force: f32,
    pub max_force: f32,
}