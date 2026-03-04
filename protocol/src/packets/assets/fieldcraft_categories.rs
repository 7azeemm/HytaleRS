use std::collections::HashMap;
use macros::packet;
use crate::packets::assets::item_category::ItemCategoryPacket;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 58, max_size = 0x64000000, compressed)]
pub struct UpdateFieldcraftCategories {
    pub update_type: UpdateType,
    pub item_categories: HashMap<i32, ItemCategoryPacket>,
}