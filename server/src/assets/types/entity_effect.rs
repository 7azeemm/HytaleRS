use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::entity_effect::{EntityEffectPacket, OverlapBehavior, UpdateEntityEffects, ValueType};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EntityEffect {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for EntityEffect {
    type InitPacketType = UpdateEntityEffects;

    fn name() -> &'static str {
        "EntityEffects"
    }

    fn path() -> &'static str {
        "Entity/Effects"
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

    fn generate_init_packet(
        map: RwLockReadGuard<RawRwLock, HashMap<String, Asset<Self>>>
    ) -> Self::InitPacketType {
        let mut entity_effects = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            entity_effects.insert(i as i32, EntityEffectPacket {
                world_removal_sound_event_index: 0,
                local_removal_sound_event_index: 0,
                duration: 0.0,
                infinite: false,
                debuff: false,
                overlap_behavior: OverlapBehavior::Extend,
                damage_calculator_cooldown: 0.0,
                value_type: ValueType::Percent,
                id: Some(id.clone()),
                name: None,
                application_effects: None,
                model_override: None,
                status_effect_icon: None,
                stat_modifiers: Default::default(),
            });
        }

        UpdateEntityEffects {
            update_type: UpdateType::Init,
            max_id: entity_effects.len() as i32,
            entity_effects,
        }
    }
}
