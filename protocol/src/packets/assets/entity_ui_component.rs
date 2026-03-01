use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, RangeVec2f, Vec2f};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 73, max_size = 0x64000000, compressed)]
pub struct UpdateEntityUIComponents {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub components: HashMap<i32, EntityUIComponentPacket>,
}

#[packet_field]
pub struct EntityUIComponentPacket {
    pub component_type: EntityUIType,
    pub hitbox_offset: FixedOption<Vec2f>,
    pub unknown: bool,
    pub entity_stat_index: i32,
    pub combat_text_random_position_offset_range: FixedOption<RangeVec2f>,
    pub combat_text_viewport_margin: f32,
    pub combat_text_duration: f32,
    pub combat_text_hit_angle_modifier_strength: f32,
    pub combat_text_font_size: f32,
    pub combat_text_color: FixedOption<Color>,
    pub combat_text_animation_events: Vec<CombatTextEntityUIComponentAnimationEvent>
}

#[packet_field]
pub struct CombatTextEntityUIComponentAnimationEvent {
    pub event_type: CombatTextEntityUIAnimationEventType,
    pub start_at: f32,
    pub end_at: f32,
    pub start_scale: f32,
    pub end_scale: f32,
    pub position_offset: FixedOption<Vec2f>,
    pub start_opacity: f32,
    pub end_opacity: f32,
}

#[packet_enum]
pub enum EntityUIType {
    EntityStat,
    CombatText
}

#[packet_enum]
pub enum CombatTextEntityUIAnimationEventType {
    Scale,
    Position,
    Opacity
}