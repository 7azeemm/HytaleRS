use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 56, max_size = 0x64000000, compressed)]
pub struct UpdateItemCategories {
    pub update_type: UpdateType,
    pub item_categories: Vec<ItemCategoryPacket>,
}

#[packet_field]
pub struct ItemCategoryPacket {
    pub order: i32,
    pub info_display_mode: ItemGridInfoDisplayMode,
    pub id: Option<String>,
    pub name: Option<String>,
    pub icon: Option<String>,
    pub children: Vec<ItemCategoryPacket>,
    pub sub_categories: Vec<SubCategoryDefinition>
}

#[packet_field]
pub struct SubCategoryDefinition {
    pub order: i32,
    pub id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Default)]
#[packet_enum]
pub enum ItemGridInfoDisplayMode {
    #[default]
    Tooltip,
    Adjacent,
    None
}