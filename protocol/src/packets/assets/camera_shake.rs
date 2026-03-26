use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 77, max_size = 0x64000000, compressed)]
pub struct UpdateCameraShake {
    pub update_type: UpdateType,
    pub profiles: HashMap<i32, CameraShakePacket>,
}

#[packet_field]
pub struct CameraShakePacket {
    pub first_person: Option<CameraShakeConfig>,
    pub third_person: Option<CameraShakeConfig>,
}

#[packet_field]
pub struct CameraShakeConfig {
    pub duration: f32,
    pub start_time: f32,
    pub continuous: bool,
    pub ease_in: FixedOption<EasingConfig>,
    pub ease_out: FixedOption<EasingConfig>,
    pub offset: Option<OffsetNoise>,
    pub rotation: Option<RotationNoise>
}

#[packet_field]
pub struct EasingConfig {
    pub time: f32,
    pub easing_type: EasingType,
}

#[packet_field]
pub struct OffsetNoise {
    pub x: Vec<NoiseConfig>,
    pub y: Vec<NoiseConfig>,
    pub z: Vec<NoiseConfig>,
}

#[packet_field]
pub struct RotationNoise {
    pub pitch: Vec<NoiseConfig>,
    pub yaw: Vec<NoiseConfig>,
    pub roll: Vec<NoiseConfig>,
}

#[packet_field]
pub struct NoiseConfig {
    pub seed: i32,
    pub noise_type: NoiseType,
    pub frequency: f32,
    pub amplitude: f32,
    pub clamp: FixedOption<ClampConfig>
}

#[packet_field]
pub struct ClampConfig {
    pub min: f32,
    pub max: f32,
    pub normalize: bool
}

#[packet_enum]
pub enum NoiseType {
    Sin,
    Cos,
    PerlinLinear,
    PerlinHermite,
    PerlinQuintic,
    Random
}

#[packet_enum]
pub enum EasingType {
    Linear,
    QuadIn,
    QuadOut,
    QuadInOut,
    CubicIn,
    CubicOut,
    CubicInOut,
    QuartIn,
    QuartOut,
    QuartInOut,
    QuintIn,
    QuintOut,
    QuintInOut,
    SineIn,
    SineOut,
    SineInOut,
    ExpoIn,
    ExpoOut,
    ExpoInOut,
    CircIn,
    CircOut,
    CircInOut,
    ElasticIn,
    ElasticOut,
    ElasticInOut,
    BackIn,
    BackOut,
    BackInOut,
    BounceIn,
    BounceOut,
    BounceInOut
}