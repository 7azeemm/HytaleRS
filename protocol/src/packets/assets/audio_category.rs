use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 80, max_size = 0x64000000, compressed)]
pub struct UpdateAudioCategories {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub categories: HashMap<i32, AudioCategoryPacket>,
}

#[packet_field]
pub struct AudioCategoryPacket {
    pub volume: f32,
    pub id: Option<String>,
}