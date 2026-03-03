use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Direction, RangeFloat, RangeVec3f, Vec3f};
use crate::packets::assets::particle_spawner::{InitialVelocity, ParticleAttractorPacket};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 49, max_size = 0x64000000, compressed)]
pub struct UpdateParticleSystems {
    pub update_type: UpdateType,
    pub systems: HashMap<String, ParticleSystemPacket>,
    pub removed_systems: Vec<String>
}

#[packet_field]
pub struct ParticleSystemPacket {
    pub life_span: f32,
    pub cull_distance: f32,
    pub bounding_radius: f32,
    pub is_important: bool,
    pub id: Option<String>,
    pub spawners: Vec<ParticleSpawnerGroupPacket>,
}

#[packet_field]
pub struct ParticleSpawnerGroupPacket {
    pub position_offset: FixedOption<Vec3f>,
    pub rotation_offset: FixedOption<Direction>,
    pub fixed_rotation: bool,
    pub start_delay: f32,
    pub spawn_rate: FixedOption<RangeFloat>,
    pub wave_delay: FixedOption<RangeFloat>,
    pub total_spawners: i32,
    pub max_concurrent: i32,
    pub initial_velocity: FixedOption<InitialVelocity>,
    pub emit_offset: FixedOption<RangeVec3f>,
    pub life_span: FixedOption<RangeFloat>,
    pub spawner_id: Option<String>,
    pub attractors: Vec<ParticleAttractorPacket>
}