use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{FloatRange, HitBox};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 42, max_size = 0x64000000, compressed)]
pub struct UpdateBlockSoundSets {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub block_sound_sets: HashMap<i32, BlockSoundSetPacket>,
}

#[packet_field]
pub struct BlockSoundSetPacket {
    pub move_in_repeat_range: FixedOption<FloatRange>,
    pub id: Option<String>,
    pub sound_event_indices: HashMap<BlockSoundEvent, i32>,
}

#[packet_enum]
#[derive(Hash, Eq, PartialEq)]
pub enum BlockSoundEvent {
    Walk,
    Land,
    MoveIn,
    MoveOut,
    Hit,
    Break,
    Build,
    Clone,
    Harvest
}