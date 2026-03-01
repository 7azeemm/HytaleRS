use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 57, max_size = 0x64000000, compressed)]
pub struct UpdateItemReticles {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub item_reticle_configs: HashMap<i32, ItemReticleConfig>,
}

#[packet_field]
pub struct ItemReticleConfig {
    pub id: Option<String>,
    pub base: Vec<String>,
    pub server_events: HashMap<i32, ItemReticle>,
    pub client_events: HashMap<ItemReticleClientEvent, ItemReticle>
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
#[packet_field]
pub struct ItemReticle {
    pub hide_base: bool,
    pub duration: f32,
    pub parts: Vec<String>,
}

#[packet_enum]
#[derive(Hash, Eq, PartialEq)]
pub enum ItemReticleClientEvent {
    OnHit,
    Wielding,
    OnMovementLeft,
    OnMovementRight,
    OnMovementBack
}