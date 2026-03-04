use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::entity_ui_component::{CombatTextEntityUIAnimationEventType, CombatTextEntityUIComponentAnimationEvent, EntityUIComponentPacket, EntityUIType, UpdateEntityUIComponents};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

//FIXME: in wrong place and is abstract asset

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EntityUIComponent {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for EntityUIComponent {
    type InitPacketType = UpdateEntityUIComponents;

    fn name() -> &'static str {
        "EntityUIComponents"
    }

    fn path() -> &'static str {
        "Entity/UI"
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
        let mut components = HashMap::new();

        for (i, (_, asset)) in map.iter().enumerate() {
            components.insert(i as i32, EntityUIComponentPacket {
                component_type: EntityUIType::EntityStat,
                hitbox_offset: Default::default(),
                unknown: false,
                entity_stat_index: 0,
                combat_text_random_position_offset_range: Default::default(),
                combat_text_viewport_margin: 0.0,
                combat_text_duration: 0.0,
                combat_text_hit_angle_modifier_strength: 0.0,
                combat_text_font_size: 0.0,
                combat_text_color: Default::default(),
                combat_text_animation_events: vec![CombatTextEntityUIComponentAnimationEvent {
                    event_type: CombatTextEntityUIAnimationEventType::Scale,
                    start_at: 0.0,
                    end_at: 0.0,
                    start_scale: 0.0,
                    end_scale: 0.0,
                    position_offset: Default::default(),
                    start_opacity: 0.0,
                    end_opacity: 0.0,
                }],
            });
            break;
        }

        UpdateEntityUIComponents {
            update_type: UpdateType::Init,
            max_id: map.len() as i32,
            components
        }
    }
}