use std::collections::HashMap;
use macros::packet;
use crate::io::codecs::VarList;
use crate::objects::HitBox;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 41, max_size = 0x64000000, compressed)]
pub struct UpdateBlockHitBoxes {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub block_hitboxes: HashMap<i32, VarList<HitBox, 64>>,
}