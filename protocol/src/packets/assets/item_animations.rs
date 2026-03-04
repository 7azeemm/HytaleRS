use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{RangeFloat, Vec3f};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 52, max_size = 0x64000000, compressed)]
pub struct UpdateItemPlayerAnimations {
    pub update_type: UpdateType,
    pub item_player_animations: HashMap<String, ItemPlayerAnimationsPacket>,
}

#[packet_field]
pub struct ItemPlayerAnimationsPacket {
    pub wiggle_weights: FixedOption<WiggleWeightsPacket>,
    pub pullback_config: FixedOption<ItemPullbackConfigPacket>,
    pub use_first_person_override: bool,
    pub id: Option<String>,
    pub animations: HashMap<String, ItemAnimationPacket>,
    pub camera: Option<CameraSettingsPacket>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
#[packet_field]
pub struct WiggleWeightsPacket {
    pub x: f32,
    pub x_deceleration: f32,
    pub y: f32,
    pub y_deceleration: f32,
    pub z: f32,
    pub z_deceleration: f32,
    pub roll: f32,
    pub roll_deceleration: f32,
    pub pitch: f32,
    pub pitch_deceleration: f32
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
#[packet_field]
pub struct ItemPullbackConfigPacket {
    pub left_offset_override: FixedOption<Vec3f>,
    pub left_rotation_override: FixedOption<Vec3f>,
    pub right_offset_override: FixedOption<Vec3f>,
    pub right_rotation_override: FixedOption<Vec3f>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
#[packet_field]
pub struct ItemAnimationPacket {
    pub keep_previous_first_person_animation: bool,
    pub speed: f32,
    pub blending_duration: f32,
    pub looping: bool,
    pub clips_geometry: bool,
    pub third_person: Option<String>,
    pub third_person_moving: Option<String>,
    pub third_person_face: Option<String>,
    pub first_person: Option<String>,
    pub first_person_override: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
#[packet_field]
pub struct CameraSettingsPacket {
    pub position_offset: FixedOption<Vec3f>,
    pub yaw: Option<CameraAxis>,
    pub pitch: Option<CameraAxis>
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
#[packet_field]
pub struct CameraAxis {
    pub angle_range: FixedOption<RangeFloat>,
    pub target_nodes: Vec<CameraNode>
}

#[packet_enum]
pub enum CameraNode {
    None,
    Head,
    LShoulder,
    RShoulder,
    Belly
}