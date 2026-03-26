use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 79, max_size = 0x64000000, compressed)]
pub struct UpdateSoundSets {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub sound_sets: HashMap<i32, SoundSetPacket>,
}

#[packet_field]
pub struct SoundSetPacket {
    pub category: SoundCategory,
    pub id: Option<String>,
    pub sounds: HashMap<String, i32>,
}

#[packet_enum]
pub enum SoundCategory {
    Music,
    Ambient,
    SFX,
    UI,
    Voice
}