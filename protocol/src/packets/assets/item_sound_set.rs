use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 43, max_size = 0x64000000, compressed)]
pub struct UpdateItemSoundSets {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub item_sound_sets: HashMap<i32, ItemSoundSetPacket>,
}

#[packet_field]
pub struct ItemSoundSetPacket {
    pub id: Option<String>,
    pub sound_event_indices: HashMap<ItemSoundEvent, i32>
}

#[packet_enum]
#[derive(Hash, Eq, PartialEq)]
pub enum ItemSoundEvent {
    Drag,
    Drop
}