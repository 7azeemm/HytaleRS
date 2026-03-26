use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::camera_shake::{CameraShakePacket, UpdateCameraShake};
use protocol::packets::assets::entity_effect::{EntityEffectPacket, OverlapBehavior, UpdateEntityEffects, ValueType};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct CameraShake {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for CameraShake {
    type InitPacketType = UpdateCameraShake;

    fn name() -> &'static str {
        "CameraShake"
    }

    fn path() -> &'static str {
        "Camera/CameraShake"
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
        let mut profiles = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            profiles.insert(i as i32, CameraShakePacket {
                first_person: None,
                third_person: None,
            });
        }

        UpdateCameraShake {
            update_type: UpdateType::Init,
            profiles,
        }
    }
}
