use serde::{Deserialize, Serialize};
use macros::packet_field;

#[derive(Serialize, Deserialize)]
#[packet_field]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8
}

#[derive(Serialize, Deserialize)]
#[packet_field]
pub struct Direction {
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32
}

#[derive(Serialize, Deserialize)]
#[packet_field]
pub struct Vec3f {
    pub x: f32,
    pub y: f32,
    pub z: f32
}