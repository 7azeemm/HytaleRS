use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use macros::{packet, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 65, max_size = 0x64000000, compressed)]
pub struct UpdateSoundEvents {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub sound_events: HashMap<i32, SoundEventPacket>,
}

#[packet_field]
pub struct SoundEventPacket {
    pub volume: f32,
    pub pitch: f32,
    pub music_ducking_volume: f32,
    pub ambient_ducking_volume: f32,
    pub max_instance: i32,
    pub prevent_sound_interruption: bool,
    pub start_attenuation_distance: f32,
    pub max_distance: f32,
    pub audio_category: i32,
    pub id: Option<String>,
    pub layers: Vec<SoundEventLayerPacket>
}

#[derive(Serialize, Deserialize)]
#[packet_field]
pub struct SoundEventLayerPacket {
    pub volume: f32,
    pub start_delay: f32,
    pub looping: bool,
    pub probability: i32,
    pub probability_reroll_delay: f32,
    pub round_robin_history_size: i32,
    pub random_settings: Option<RandomSettingsPacket>,
    pub files: Vec<String>
}

#[derive(Serialize, Deserialize)]
#[packet_field]
pub struct RandomSettingsPacket {
    pub min_volume: f32,
    pub max_volume: f32,
    pub min_pitch: f32,
    pub max_pitch: f32,
    pub max_start_offset: f32,
}