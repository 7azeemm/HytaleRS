use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 74, max_size = 36864011, compressed)]
pub struct UpdateHitboxCollisionConfigs {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub hitbox_collision_configs: HashMap<i32, HitboxCollisionConfigPacket>,
}

#[packet_field]
pub struct HitboxCollisionConfigPacket {
    pub collision_type: CollisionType,
    pub soft_collision_offset_ratio: f32
}

#[packet_enum]
pub enum CollisionType {
    Hard,
    Soft
}