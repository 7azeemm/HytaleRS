use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 81, max_size = 0x64000000, compressed)]
pub struct UpdateReverbEffects {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub effects: HashMap<i32, ReverbEffectPacket>,
}

#[packet_field]
pub struct ReverbEffectPacket {
    pub dry_gain: f32,
    pub modal_density: f32,
    pub diffusion: f32,
    pub gain: f32,
    pub high_frequency_gain: f32,
    pub decay_time: f32,
    pub high_frequency_decay_ratio: f32,
    pub reflection_gain: f32,
    pub reflection_delay: f32,
    pub late_reverb_gain: f32,
    pub late_reverb_delay: f32,
    pub room_roll_off_factor: f32,
    pub air_absorption_high_frequency_gain: f32,
    pub limit_decay_high_frequency: bool,
    pub id: Option<String>,
}