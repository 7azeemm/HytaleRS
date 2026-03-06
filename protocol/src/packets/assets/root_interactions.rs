use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::interaction_type::InteractionType;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 67, max_size = 0x64000000, compressed)]
pub struct UpdateRootInteractions {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub interactions: HashMap<i32, RootInteractionPacket>,
}

#[packet_field]
pub struct RootInteractionPacket {
    pub click_queuing_timeout: f32,
    pub require_new_click: bool,
    pub id: Option<String>,
    pub interactions: Vec<i32>,
    pub cooldown: Option<InteractionCooldown>,
    pub settings: HashMap<GameMode, RootInteractionSettings>,
    pub rules: Option<InteractionRules>,
    pub tags: Vec<i32>
}

#[packet_field]
pub struct InteractionCooldown {
    pub cooldown: f32,
    pub click_bypass: bool,
    pub skip_cooldown_reset: bool,
    pub interrupt_recharge: bool,
    pub cooldown_id: Option<String>,
    pub charge_times: Vec<f32>
}

#[packet_field]
pub struct RootInteractionSettings {
    pub allow_skip_chain_on_click: bool,
    pub cooldown: Option<InteractionCooldown>
}

#[packet_field]
pub struct InteractionRules {
    pub blocked_by_bypass_index: i32,
    pub blocking_bypass_index: i32,
    pub interrupted_by_bypass_index: i32,
    pub interrupting_bypass_index: i32,
    pub blocked_by: Vec<InteractionType>,
    pub blocking: Vec<InteractionType>,
    pub interrupted_by: Vec<InteractionType>,
    pub interrupting: Vec<InteractionType>,
}

#[packet_enum]
#[derive(Eq, PartialEq, Hash)]
pub enum GameMode {
    Adventure,
    Creative
}