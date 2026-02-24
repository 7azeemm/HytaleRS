use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::Color;
use crate::packets::assets::shader_type::ShaderType;
use crate::packets::assets::update_type::UpdateType;
use crate::packets::assets::weather::NearFogPacket;

#[packet(id = 63, max_size = 0x64000000, compressed)]
pub struct UpdateFluidFX {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub fluid_fx: HashMap<i32, FluidFXPacket>,
}

#[packet_field]
pub struct FluidFXPacket {
    pub shader: ShaderType,
    pub fog_mode: FluidFog,
    pub fog_color: FixedOption<Color>,
    pub fog_distance: FixedOption<NearFogPacket>,
    pub fog_depth_start: f32,
    pub fog_depth_falloff: f32,
    pub colors_filter: FixedOption<Color>,
    pub colors_saturation: f32,
    pub distortion_amplitude: f32,
    pub distortion_frequency: f32,
    pub movement_settings: FixedOption<FluidFXMovementSettings>,
    pub id: Option<String>,
    pub particle: Option<FluidParticlePacket>,
}

#[packet_enum]
pub enum FluidFog {
    Color,
    ColorLight,
    EnvironmentTint
}

#[packet_field]
pub struct FluidParticlePacket {
    pub color: FixedOption<String>,//Color
    pub scale: f32,
    pub system_id: Option<String>
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
#[packet_field]
pub struct FluidFXMovementSettings {
    pub swim_up_speed: f32,
    pub swim_down_speed: f32,
    pub sink_speed: f32,
    pub horizontal_speed_multiplier: f32,
    pub field_of_view_multiplier: f32,
    pub entry_velocity_multiplier: f32,
}