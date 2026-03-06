use serde::{Deserialize, Serialize};
use macros::{packet_enum, packet_field};
use crate::io::codecs::FixedOption;

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct Color {
    pub red: u8,
    pub green: u8,
    pub blue: u8
}

//FIXME: these have custom serialize/deserialize logic
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct ColorAlpha {
    pub alpha: u8,
    pub red: u8,
    pub green: u8,
    pub blue: u8
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct ColorLight {
    pub radius: u8,
    pub red: u8,
    pub green: u8,
    pub blue: u8
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct Direction {
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct Vec3f {
    pub x: f32,
    pub y: f32,
    pub z: f32
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct Vec2f {
    pub x: f32,
    pub y: f32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct Vec2i {
    pub x: i32,
    pub y: i32,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct Vec3d {
    pub x: f64,
    pub y: f64,
    pub z: f64
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct Vec3i {
    pub x: i32,
    pub y: i32,
    pub z: i32
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct HitBox {
    pub min: Vec3d,
    pub max: Vec3d,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct FloatRange {
    pub min: f32,
    pub max: f32,
}

impl FloatRange {
    pub fn new(min: f32, max: f32) -> Self {
        Self { min, max }
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct Range {
    pub min: i32,
    pub max: i32,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct RangeByte {
    pub min: u8,
    pub max: u8,
}

//TODO: impl Copy to some structs
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct RangeFloat {
    pub min: f32,
    pub max: f32,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct RangeVec3f {
    pub x: FixedOption<RangeFloat>,
    pub y: FixedOption<RangeFloat>,
    pub z: FixedOption<RangeFloat>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct RangeVec2f {
    pub x: FixedOption<RangeFloat>,
    pub y: FixedOption<RangeFloat>,
}

#[packet_enum]
pub enum Opacity {
    Solid,
    SemiTransparent,
    Cutout,
    Transparent
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[packet_field]
pub struct Size {
    pub width: i32,
    pub height: i32,
}