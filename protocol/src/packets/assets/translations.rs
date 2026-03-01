use std::collections::HashMap;
use macros::packet;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 64, max_size = 0x64000000, compressed)]
pub struct UpdateTranslations {
    pub update_type: UpdateType,
    pub translations: HashMap<String, String>,
}