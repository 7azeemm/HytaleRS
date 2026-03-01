use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::repulsion::{RepulsionConfigPacket, UpdateRepulsionConfigs};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

//FIXME: in wrong place

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct RepulsionConfig {
    pub id: String,
    pub parent: Option<String>,
    pub radius: f32,
    pub min_force: f32,
    pub max_force: f32,
}

impl AssetType for RepulsionConfig {
    type InitPacketType = UpdateRepulsionConfigs;

    fn name() -> &'static str {
        "Repulsion"
    }

    fn path() -> &'static str {
        "Entity/Repulsion"
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
        let mut repulsion_configs = HashMap::new();

        for (i, (_, asset)) in map.iter().enumerate() {
            repulsion_configs.insert(i as i32, RepulsionConfigPacket {
                radius: asset.data.radius,
                min_force: asset.data.min_force,
                max_force: asset.data.max_force,
            });
        }

        UpdateRepulsionConfigs {
            update_type: UpdateType::Init,
            max_id: map.len() as i32,
            repulsion_configs
        }
    }
}