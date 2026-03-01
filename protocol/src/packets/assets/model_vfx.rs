use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, Vec2f};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 53, max_size = 0x64000000, compressed)]
pub struct UpdateModelVFXs {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub model_vfx: HashMap<i32, ModelVFXPacket>,
}

#[packet_field]
pub struct ModelVFXPacket {
    pub switch_to: SwitchTo,
    pub effect_direction: EffectDirection,
    pub animation_duration: f32,
    pub animation_range: FixedOption<Vec2f>,
    pub loop_option: LoopOption,
    pub curve_type: CurveType,
    pub highlight_color: FixedOption<Color>,
    pub highlight_thickness: f32,
    pub use_bloom_on_highlight: bool,
    pub use_progressive_highlight: bool,
    pub noise_scale: FixedOption<Vec2f>,
    pub noise_scroll_speed: FixedOption<Vec2f>,
    pub post_color: FixedOption<Color>,
    pub post_color_opacity: f32,
    pub id: Option<String>,
}

#[packet_enum]
pub enum SwitchTo {
    Disappear,
    PostColor,
    Distortion,
    Transparency
}

#[packet_enum]
pub enum EffectDirection {
    None,
    BottomUp,
    TopDown,
    ToCenter,
    FromCenter
}

#[packet_enum]
pub enum LoopOption {
    PlayOnce,
    Loop,
    LoopMirror
}

#[packet_enum]
pub enum CurveType {
    Linear,
    QuartIn,
    QuartOut,
    QuartInOut
}