use std::collections::HashMap;
use ordered_float::OrderedFloat;
use macros::{packet, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, ColorAlpha};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 47, max_size = 0x64000000, compressed)]
pub struct UpdateWeathers {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub weathers: HashMap<i32, WeatherPacket>,
}

#[packet_field]
pub struct WeatherPacket {
    pub fog: FixedOption<NearFogPacket>,
    pub fog_options: FixedOption<FogOptionsPacket>,
    pub id: Option<String>,
    pub tag_indexes: Vec<i32>,
    pub stars: Option<String>,
    pub moons: HashMap<i32, String>,
    pub clouds: Vec<CloudPacket>,
    pub sunlight_damping_multiplier: HashMap<OrderedFloat<f32>, f32>,
    pub sunlight_colors: HashMap<OrderedFloat<f32>, Color>,
    pub sky_top_colors: HashMap<OrderedFloat<f32>, ColorAlpha>,
    pub sky_bottom_colors: HashMap<OrderedFloat<f32>, ColorAlpha>,
    pub sky_sunset_colors: HashMap<OrderedFloat<f32>, ColorAlpha>,
    pub sun_colors: HashMap<OrderedFloat<f32>, Color>,
    pub sun_scales: HashMap<OrderedFloat<f32>, f32>,
    pub sun_glow_colors: HashMap<OrderedFloat<f32>, ColorAlpha>,
    pub moon_colors: HashMap<OrderedFloat<f32>, ColorAlpha>,
    pub moon_scales: HashMap<OrderedFloat<f32>, f32>,
    pub moon_glow_colors: HashMap<OrderedFloat<f32>, ColorAlpha>,
    pub fog_colors: HashMap<OrderedFloat<f32>, Color>,
    pub fog_height_fall_offs: HashMap<OrderedFloat<f32>, f32>,
    pub fog_densities: HashMap<OrderedFloat<f32>, f32>,
    pub screen_effect: Option<String>,
    pub screen_effect_colors: HashMap<OrderedFloat<f32>, ColorAlpha>,
    pub color_filters: HashMap<OrderedFloat<f32>, Color>,
    pub water_tints: HashMap<OrderedFloat<f32>, Color>,
    pub weather_particle: Option<WeatherParticlePacket>,
}

#[packet_field]
pub struct CloudPacket {
    pub texture: Option<String>,
    pub speeds: HashMap<OrderedFloat<f32>, f32>,
    pub colors: HashMap<OrderedFloat<f32>, ColorAlpha>
}

#[packet_field]
pub struct WeatherParticlePacket {
    pub color: FixedOption<Color>,
    pub scale: f32,
    pub overground_only: bool,
    pub position_offset_multiplier: f32,
    pub system_id: Option<String>,
}

#[packet_field]
pub struct NearFogPacket {
    pub near: f32,
    pub far: f32,
}

#[packet_field]
pub struct FogOptionsPacket {
    pub ignore_fog_limits: bool,
    pub effective_view_distance_multiplier: f32,
    pub fog_far_view_distance: f32,
    pub fog_height_camera_offset: f32,
    pub fog_height_camera_overridden: bool,
    pub fog_height_camera_fixed: f32,
}