use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::environment::{UpdateEnvironments, WorldEnvironmentPacket};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Environment {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for Environment {
    type InitPacketType = UpdateEnvironments;

    fn name() -> &'static str {
        "Environments"
    }

    fn path() -> &'static str {
        "Environments"
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
        let mut environments = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            environments.insert(i as i32, WorldEnvironmentPacket {
                color_tint: Default::default(),
                id: Some(id.clone()),
                fluid_particles: Default::default(),
                tag_indexes: vec![],
            });
        }

        UpdateEnvironments {
            update_type: UpdateType::Init,
            max_id: environments.len() as i32,
            environments,
            rebuild_map_geometry: true,
        }
    }
}
