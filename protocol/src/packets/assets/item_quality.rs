use std::collections::HashMap;
use macros::{packet, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::Color;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 55, max_size = 0x64000000, compressed)]
pub struct UpdateItemQualities {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub item_qualities: HashMap<i32, ItemQualityPacket>,
}

#[packet_field]
pub struct ItemQualityPacket {
    pub text_color: FixedOption<Color>,
    pub visible_quality_label: bool,
    pub render_special_slot: bool,
    pub hide_from_search: bool,
    pub id: Option<String>,
    pub item_tooltip_texture: Option<String>,
    pub item_tooltip_arrow_texture: Option<String>,
    pub slot_texture: Option<String>,
    pub block_slot_texture: Option<String>,
    pub special_slot_texture: Option<String>,
    pub localization_key: Option<String>
}