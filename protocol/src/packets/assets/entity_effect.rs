use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, RangeFloat};
use crate::packets::assets::interactions::interaction_type::InteractionType;
use crate::packets::assets::model_particle::ModelParticlePacket;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 51, max_size = 0x64000000, compressed)]
pub struct UpdateEntityEffects {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub entity_effects: HashMap<i32, EntityEffectPacket>,
}

#[packet_field]
pub struct EntityEffectPacket {
    pub world_removal_sound_event_index: i32,
    pub local_removal_sound_event_index: i32,
    pub duration: f32,
    pub infinite: bool,
    pub debuff: bool,
    pub overlap_behavior: OverlapBehavior,
    pub damage_calculator_cooldown: f64,
    pub value_type: ValueType,
    pub id: Option<String>,
    pub name: Option<String>,
    pub application_effects: Option<ApplicationEffects>,
    pub model_override: Option<ModelOverride>,
    pub status_effect_icon: Option<String>,
    pub stat_modifiers: HashMap<i32, f32>,
}

#[packet_field]
pub struct ApplicationEffects {
    pub entity_bottom_tint: FixedOption<Color>,
    pub entity_top_tint: FixedOption<Color>,
    pub horizontal_speed_multiplier: f32,
    pub sound_event_index_local: i32,
    pub sound_event_index_world: i32,
    pub movement_effects: FixedOption<MovementEffectsPacket>,
    pub mouse_sensitivity_adjustment_target: f32,
    pub mouse_sensitivity_adjustment_duration: f32,
    pub entity_animation_id: Option<String>,
    pub particles: Vec<ModelParticlePacket>,
    pub first_person_particles: Vec<ModelParticlePacket>,
    pub screen_effect: Option<String>,
    pub model_vfx_id: Option<String>,
    pub ability_effects: Option<AbilityEffects>
}

#[packet_field]
pub struct MovementEffectsPacket {
    pub disable_forward: bool,
    pub disable_backward: bool,
    pub disable_left: bool,
    pub disable_right: bool,
    pub disable_sprint: bool,
    pub disable_jump: bool,
    pub disable_crouch: bool
}

#[packet_field]
pub struct AbilityEffects {
    pub disabled: Vec<InteractionType>
}

#[packet_field]
pub struct ModelOverride {
    pub model: Option<String>,
    pub texture: Option<String>,
    pub animation_sets: HashMap<String, AnimationSet>
}

#[packet_field]
pub struct AnimationSet {
    pub next_animation_delay: FixedOption<RangeFloat>,
    pub id: Option<String>,
    pub animations: Vec<Animation>,
}

#[packet_field]
pub struct Animation {
    pub speed: f32,
    pub blending_duration: f32,
    pub looping: bool,
    pub weight: f32,
    pub sound_event_index: i32,
    pub passive_loop_count: i32,
    pub name: Option<String>,
    pub foot_step_intervals: Vec<i32>,
}

#[packet_enum]
pub enum OverlapBehavior {
    Extend,
    Overwrite,
    Ignore,
}

#[packet_enum]
pub enum ValueType {
    Percent,
    Absolute
}