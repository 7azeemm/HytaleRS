use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::item_category::{ItemCategoryPacket, ItemGridInfoDisplayMode, UpdateItemCategories};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ItemCategory {
    pub parent: Option<String>,
    pub id: String,
    pub name: String,
    pub icon: String,
    pub order: i32,
    pub info_display_mode: ItemGridInfoDisplayMode,
    pub children: Vec<ItemCategory>
}

impl AssetType for ItemCategory {
    type InitPacketType = UpdateItemCategories;

    fn name() -> &'static str {
        "ItemCategories"
    }

    fn path() -> &'static str {
        "Item/Category/CreativeLibrary"
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
        let mut item_categories = Vec::new();

        for (id, asset) in map.iter() {
            let children = asset.data.children.iter()
                .map(|c| ItemCategoryPacket {
                    order: c.order,
                    info_display_mode: c.info_display_mode,
                    id: Some(c.id.clone()),
                    name: Some(c.name.clone()),
                    icon: Some(c.icon.clone()),
                    children: vec![],
                })
                .collect();

            item_categories.push(ItemCategoryPacket {
                id: Some(id.clone()),
                name: Some(asset.data.name.clone()),
                icon: Some(asset.data.icon.clone()),
                order: asset.data.order,
                info_display_mode: asset.data.info_display_mode,
                children,
            });
        }

        UpdateItemCategories {
            update_type: UpdateType::Init,
            item_categories
        }
    }
}