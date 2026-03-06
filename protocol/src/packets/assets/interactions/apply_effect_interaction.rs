use std::collections::HashMap;
use macros::{interaction, packet_field};
use crate::packets::assets::interactions::interaction::{GameMode, InteractionCameraSettings, InteractionEffects, InteractionRules, InteractionSettings, InteractionTarget, WaitForDataFrom};

#[interaction(id = 27)]
#[packet_field]
pub struct ApplyEffectInteraction {
    pub wait_for_data_from: WaitForDataFrom,
    pub horizontal_speed_multiplier: f32,
    pub run_time: f32,
    pub cancel_on_item_change: bool,
    pub next: i32,
    pub failed: i32,
    pub effect_id: i32,
    pub entity_target: InteractionTarget,
    pub effects: Option<InteractionEffects>,
    pub settings: HashMap<GameMode, InteractionSettings>,
    pub rules: Option<InteractionRules>,
    pub tags: Vec<i32>,
    pub camera: Option<InteractionCameraSettings>,
}
