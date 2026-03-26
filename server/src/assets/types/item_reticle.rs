use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::item_reticle::{ItemReticle, ItemReticleClientEvent, ItemReticleConfig, UpdateItemReticles};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ItemReticles {
    pub id: String,
    pub parent: Option<String>,
    pub base: Vec<String>,
    pub server_events: HashMap<String, ItemReticle>,
    pub client_events: HashMap<ItemReticleClientEvent, ItemReticle>
}

impl AssetType for ItemReticles {
    type InitPacketType = UpdateItemReticles;

    fn name() -> &'static str {
        "ItemReticles"
    }

    fn path() -> &'static str {
        "Item/Reticles"
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
        let mut item_reticle_configs = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            item_reticle_configs.insert(i as i32, ItemReticleConfig {
                id: Some(asset.data.id.clone()),
                base: asset.data.base.clone(),
                server_events: Default::default(),
                client_events: Default::default(),
            });
        }

        UpdateItemReticles {
            update_type: UpdateType::Init,
            max_id: map.len() as i32,
            item_reticle_configs
        }
    }
}