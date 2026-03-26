use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::camera_shake::CameraShakePacket;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 76, max_size = 0x64000000, compressed)]
pub struct UpdateViewBobbing {
    pub update_type: UpdateType,
    pub profiles: HashMap<MovementType, ViewBobbingPacket>,
}

#[packet_field]
pub struct ViewBobbingPacket {
    pub first_person: Option<CameraShakePacket>
}

#[derive(Hash, Eq, PartialEq)]
#[packet_enum]
pub enum MovementType {
    None,
    Idle,
    Crouching,
    Walking,
    Running,
    Sprinting,
    Climbing,
    Swimming,
    Flying,
    Sliding,
    Rolling,
    Mounting,
    SprintMounting
}