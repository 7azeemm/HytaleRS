use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::hitbox_collision::{CollisionType, HitboxCollisionConfigPacket, UpdateHitboxCollisionConfigs};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

//FIXME: in wrong place

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct HitboxCollisionConfig {
    pub id: String,
    pub parent: Option<String>,
    pub collision_type: CollisionType,
    pub soft_collision_offset_ratio: f32
}

impl Default for HitboxCollisionConfig {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            parent: None,
            collision_type: CollisionType::Hard,
            soft_collision_offset_ratio: 1.0,
        }
    }
}

impl AssetType for HitboxCollisionConfig {
    type InitPacketType = UpdateHitboxCollisionConfigs;

    fn name() -> &'static str {
        "HitboxCollision"
    }

    fn path() -> &'static str {
        "Entity/HitboxCollision"
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
        let mut hitbox_collision_configs = HashMap::new();

        for (i, (_, asset)) in map.iter().enumerate() {
            hitbox_collision_configs.insert(i as i32, HitboxCollisionConfigPacket {
                collision_type: asset.data.collision_type,
                soft_collision_offset_ratio: asset.data.soft_collision_offset_ratio,
            });
        }

        UpdateHitboxCollisionConfigs {
            update_type: UpdateType::Init,
            max_id: map.len() as i32,
            hitbox_collision_configs
        }
    }
}