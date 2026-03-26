use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::fieldcraft_categories::{UpdateFieldcraftCategories};
use protocol::packets::assets::item_category::{ItemCategoryPacket, ItemGridInfoDisplayMode};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct FieldcraftCategories {
    pub parent: Option<String>,
    pub id: String,
    pub name: String,
    pub icon: String,
    pub order: i32
}

impl AssetType for FieldcraftCategories {
    type InitPacketType = UpdateFieldcraftCategories;

    fn name() -> &'static str {
        "FieldcraftCategories"
    }

    fn path() -> &'static str {
        "Item/Category/Fieldcraft"
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
        let mut item_categories = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            item_categories.insert(i as i32, ItemCategoryPacket {
                id: Some(id.clone()),
                name: None,
                icon: Some(asset.data.icon.clone()),
                order: 0,
                info_display_mode: ItemGridInfoDisplayMode::Tooltip,
                children: vec![],
                sub_categories: vec![],
            });
        }

        UpdateFieldcraftCategories {
            update_type: UpdateType::Init,
            item_categories
        }
    }
}