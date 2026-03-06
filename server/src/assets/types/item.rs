use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::item::{ItemBasePacket, UpdateItems};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Item {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for Item {
    type InitPacketType = UpdateItems;

    fn name() -> &'static str {
        "Items"
    }

    fn path() -> &'static str {
        "Item/Items"
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
        let mut items = HashMap::new();

        for (id, asset) in map.iter() {
            items.insert(id.clone(), ItemBasePacket {
                scale: 0.0,
                use_player_animations: false,
                max_stack: 0,
                reticle_index: 0,
                icon_properties: Default::default(),
                item_level: 0,
                quality_index: 0,
                consumable: false,
                variant: false,
                block_id: 0,
                glider_config: Default::default(),
                block_selector_tool: Default::default(),
                light: Default::default(),
                durability: 0.0,
                sound_event_index: 0,
                item_sound_set_index: 0,
                pullback_config: Default::default(),
                clips_geometry: false,
                render_deployable_preview: false,
                id: None,
                model: None,
                texture: None,
                animation: None,
                player_animations_id: None,
                icon: None,
                translation_properties: None,
                resource_types: vec![],
                tool: None,
                weapon: None,
                armor: None,
                utility: None,
                builder_tool_data: None,
                item_entity: None,
                set: None,
                categories: vec![],
                particles: vec![],
                first_person_particles: vec![],
                trails: vec![],
                interactions: Default::default(),
                interaction_vars: Default::default(),
                interaction_config: None,
                dropped_item_animation: None,
                tag_indexes: vec![],
                item_appearance_conditions: Default::default(),
                display_entity_stats_hud: vec![],
            });
            break;
        }

        UpdateItems {
            update_type: UpdateType::Init,
            update_models: true,
            update_icons: true,
            items,
            removed_items: vec![],
        }
    }
}
