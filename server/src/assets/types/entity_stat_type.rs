use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::entity_stat_type::{EntityStatResetBehavior, EntityStatTypePacket, UpdateEntityStatTypes};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};
use crate::assets::types::model_particle::ModelParticle;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct EntityStatType {
    pub id: String,
    pub parent: Option<String>,
    pub initial_value: f32,
    pub min: f32,
    pub max: f32,
    pub shared: bool,
    pub regenerating: Vec<Regenerating>,
    pub ignore_invulnerability: bool,
    pub hide_from_tooltip: bool,
    pub min_value_effects: Option<EntityStatEffects>,
    pub max_value_effects: Option<EntityStatEffects>,
    pub reset_behavior: EntityStatResetBehavior,
}

impl Default for EntityStatType {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            parent: None,
            initial_value: 0.0,
            min: 0.0,
            max: 0.0,
            shared: false,
            regenerating: vec![],
            ignore_invulnerability: false,
            hide_from_tooltip: false,
            min_value_effects: None,
            max_value_effects: None,
            reset_behavior: EntityStatResetBehavior::InitialValue,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Regenerating {
    pub interval: f32,
    pub amount: f32,
    pub clamp_at_zero: bool,
    // pub regen_type: RegenType,
    // pub conditions: Vec<Condition>,
    // pub modifiers: Vec<RegeneratingModifier>
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EntityStatEffects {
    pub trigger_at_zero: bool,
    pub sound_event_id: Option<String>,
    pub sound_event_index: i32,
    pub particles: Vec<ModelParticle>,
    pub interactions: String,
}

impl AssetType for EntityStatType {
    type InitPacketType = UpdateEntityStatTypes;

    fn name() -> &'static str {
        "EntityStatTypes"
    }

    fn path() -> &'static str {
        "Entity/Stats"
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    fn generate_init_packet(map: RwLockReadGuard<RawRwLock, HashMap<String, Asset<Self>>>) -> Self::InitPacketType {
        let mut types = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            types.insert(i as i32, EntityStatTypePacket {
                value: 0.0,
                min: 0.0,
                max: 0.0,
                reset_behavior: EntityStatResetBehavior::InitialValue,
                hide_from_tooltip: false,
                id: Some(id.clone()),
                min_value_effects: None,
                max_value_effects: None,
            });
            break;
        }

        UpdateEntityStatTypes {
            update_type: UpdateType::Init,
            max_id: map.len() as i32,
            types
        }
    }
}