use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 82, max_size = 0x64000000, compressed)]
pub struct UpdateEqualizerEffects {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub effects: HashMap<i32, EqualizerEffectPacket>,
}

#[packet_field]
pub struct EqualizerEffectPacket {
    pub low_gain: f32,
    pub low_cut_off: f32,
    pub low_mid_gain: f32,
    pub low_mid_center: f32,
    pub low_mid_width: f32,
    pub high_mid_gain: f32,
    pub high_mid_center: f32,
    pub high_mid_width: f32,
    pub high_gain: f32,
    pub high_cut_off: f32,
    pub id: Option<String>,
}