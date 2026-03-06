use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::Color;
use crate::packets::assets::fluid_fx::FluidParticlePacket;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 61, max_size = 0x64000000, compressed)]
pub struct UpdateEnvironments {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub rebuild_map_geometry: bool,
    pub environments: HashMap<i32, WorldEnvironmentPacket>,
}

#[packet_field]
pub struct WorldEnvironmentPacket {
    pub color_tint: FixedOption<Color>,
    pub id: Option<String>,
    pub fluid_particles: HashMap<i32, FluidParticlePacket>,
    pub tag_indexes: Vec<i32>
}