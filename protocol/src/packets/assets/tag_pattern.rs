use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 84, max_size = 0x64000000, compressed)]
pub struct UpdateTagPatterns {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub patterns: HashMap<i32, TagPatternPacket>,
}

#[packet_field]
pub struct TagPatternPacket {
    pub tag_type: TagPatternType,
    pub tag_index: i32,
    pub operands: Vec<TagPatternPacket>,
    pub not: Option<Box<TagPatternPacket>>
}

#[packet_enum]
pub enum TagPatternType {
    Equals,
    And,
    Or,
    Not
}