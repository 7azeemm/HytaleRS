use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 58, max_size = 0x64000000, compressed)]
pub struct UpdateFieldcraftCategories {
    pub update_type: UpdateType,
    pub item_categories: HashMap<i32, ItemCategoryPacket>,
}

#[packet_field]
pub struct ItemCategoryPacket {
    pub order: i32,
    pub info_display_mode: ItemGridInfoDisplayMode,
    pub id: Option<String>,
    pub name: Option<String>,
    pub icon: Option<String>,
    pub children: Vec<ItemCategoryPacket>
}

#[packet_enum]
pub enum ItemGridInfoDisplayMode {
    Tooltip,
    Adjacent,
    None
}