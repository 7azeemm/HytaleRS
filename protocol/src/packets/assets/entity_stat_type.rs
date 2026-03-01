use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::model_particle::ModelParticlePacket;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 72, max_size = 0x64000000, compressed)]
pub struct UpdateEntityStatTypes {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub types: HashMap<i32, EntityStatTypePacket>,
}

#[packet_field]
pub struct EntityStatTypePacket {
    pub value: f32,
    pub min: f32,
    pub max: f32,
    pub reset_behavior: EntityStatResetBehavior,
    pub hide_from_tooltip: bool,
    pub id: Option<String>,
    pub min_value_effects: Option<EntityStatEffectsPacket>,
    pub max_value_effects: Option<EntityStatEffectsPacket>,
}

#[packet_field]
pub struct EntityStatEffectsPacket {
    pub trigger_at_zero: bool,
    pub sound_event_index: i32,
    pub particles: Vec<ModelParticlePacket>
}

#[packet_enum]
pub enum EntityStatResetBehavior {
    InitialValue,
    MaxValue
}

#[packet_enum]
pub enum RegenType {
    Additive,
    Percentage
}