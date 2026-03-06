use std::collections::HashMap;
use macros::packet;
use crate::packets::assets::interactions::interaction_type::InteractionType;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 68, max_size = 0x64000000, compressed)]
pub struct UpdateUnarmedInteractions {
    pub update_type: UpdateType,
    pub interactions: HashMap<InteractionType, i32>,
}