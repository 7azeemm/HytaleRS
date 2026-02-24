use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, Direction, Vec3f};
use macros::{packet, packet_enum, packet_field};
use std::collections::HashMap;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 44, max_size = 0x64000000, compressed)]
pub struct UpdateBlockParticleSets {
    pub update_type: UpdateType,
    pub block_particle_sets: HashMap<String, BlockParticleSetPacket>,
}

#[packet_field]
pub struct BlockParticleSetPacket {
    pub color: FixedOption<Color>,
    pub scale: f32,
    pub position_offset: FixedOption<Vec3f>,
    pub rotation_offset: FixedOption<Direction>,
    pub id: Option<String>,
    pub particles: HashMap<BlockParticleEvent, String>
}

#[packet_enum]
#[derive(Hash, Eq, PartialEq)]
pub enum BlockParticleEvent {
    Walk,
    Run,
    Sprint,
    SoftLand,
    HardLand,
    MoveOut,
    Hit,
    Break,
    Build,
    Physics
}