use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::resource_type::{ResourceTypePacket, UpdateResourceTypes};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ResourceTypes {
    pub parent: Option<String>,
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String
}

impl AssetType for ResourceTypes {
    type InitPacketType = UpdateResourceTypes;

    fn name() -> &'static str {
        "ResourceTypes"
    }

    fn path() -> &'static str {
        "Item/ResourceTypes"
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
        let mut resource_types = HashMap::new();

        for (id, asset) in map.iter() {
            resource_types.insert(id.clone(), ResourceTypePacket {
                id: Some(id.clone()),
                icon: Some(asset.data.icon.clone()),
            });
        }

        UpdateResourceTypes {
            update_type: UpdateType::Init,
            resource_types
        }
    }
}