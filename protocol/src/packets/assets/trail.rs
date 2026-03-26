use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use macros::{packet, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{ColorAlpha, Range, Vec2i};
use crate::packets::assets::fx_render_mode::FXRenderMode;
use crate::packets::assets::particle_spawner::IntersectionHighlightPacket;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 48, max_size = 0x64000000, compressed)]
pub struct UpdateTrails {
    pub update_type: UpdateType,
    pub trails: HashMap<String, TrailPacket>,
}

#[packet_field]
pub struct TrailPacket {
    pub life_span: i32,
    pub roll: f32,
    pub start: FixedOption<Edge>,
    pub end: FixedOption<Edge>,
    pub light_influence: f32,
    pub render_mode: FXRenderMode,
    pub intersection_highlight: IntersectionHighlightPacket,
    pub smooth: bool,
    pub frame_size: FixedOption<Vec2i>,
    pub frame_range: FixedOption<Range>,
    pub frame_life_span: i32,
    pub id: Option<String>,
    pub texture: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
#[packet_field]
pub struct Edge {
    pub width: f32,
    pub color: FixedOption<ColorAlpha>
}