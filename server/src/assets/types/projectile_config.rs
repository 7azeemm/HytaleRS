use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::projectile_config::{ProjectileConfigPacket, UpdateProjectileConfigs};
use protocol::packets::assets::repulsion::{RepulsionConfigPacket, UpdateRepulsionConfigs};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ProjectileConfig {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for ProjectileConfig {
    type InitPacketType = UpdateProjectileConfigs;

    fn name() -> &'static str {
        "ProjectileConfigs"
    }

    fn path() -> &'static str {
        "ProjectileConfigs"
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
        let mut configs = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            configs.insert(id.clone(), ProjectileConfigPacket {
                physics_config: Default::default(),
                launch_force: 0.0,
                spawn_offset: Default::default(),
                rotation_offset: Default::default(),
                launch_local_sound_event_index: 0,
                launch_world_sound_event_index: 0,
                projectile_sound_event_index: 0,
                interactions: Default::default(),
                model: None,
            });
        }

        UpdateProjectileConfigs {
            update_type: UpdateType::Init,
            configs,
            removed_configs: vec![],
        }
    }
}