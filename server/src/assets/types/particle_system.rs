use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::objects::objects::{Direction, RangeFloat, RangeVec3f, Vec3f};
use protocol::packets::assets::particle_spawner::{InitialVelocity};
use protocol::packets::assets::particle_system::{ParticleSystemPacket, UpdateParticleSystems};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};
use crate::assets::types::particle_spawner::ParticleAttractor;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ParticleSystems {
    pub id: String,
    pub parent: Option<String>,
    pub spawners: Vec<ParticleSpawnerGroup>,
    pub life_span: f32,
    pub cull_distance: f32,
    pub bounding_radius: f32,
    pub is_important: bool
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ParticleSpawnerGroup {
    pub spawner_id: Option<String>,
    pub position_offset: Option<Vec3f>,
    pub rotation_offset: Option<Direction>,
    pub fixed_rotation: bool,
    pub spawn_rate: Option<RangeFloat>,
    pub life_span: Option<RangeFloat>,
    pub start_delay: f32,
    pub wave_delay: Option<RangeFloat>,
    pub total_spawners: i32,
    pub max_concurrent: i32,
    pub initial_velocity: Option<InitialVelocity>,
    pub emit_offset: Option<RangeVec3f>,
    pub attractors: Vec<ParticleAttractor>
}

impl Default for ParticleSpawnerGroup {
    fn default() -> Self {
        Self {
            spawner_id: None,
            position_offset: None,
            rotation_offset: None,
            fixed_rotation: false,
            spawn_rate: None,
            life_span: None,
            start_delay: 0.0,
            wave_delay: None,
            total_spawners: 1,
            max_concurrent: 0,
            initial_velocity: None,
            emit_offset: None,
            attractors: vec![],
        }
    }
}

impl AssetType for ParticleSystems {
    type InitPacketType = UpdateParticleSystems;

    fn name() -> &'static str {
        "ParticleSystems"
    }

    fn path() -> &'static str {
        "Particles"
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

    fn extension() -> &'static str {
        ".particlespawner"
    }

    fn generate_init_packet(map: RwLockReadGuard<RawRwLock, HashMap<String, Asset<Self>>>) -> Self::InitPacketType {
        let mut systems = HashMap::new();

        for (id, asset) in map.iter() {
            systems.insert(id.clone(), ParticleSystemPacket {
                life_span: asset.data.life_span,
                cull_distance: asset.data.cull_distance,
                bounding_radius: asset.data.bounding_radius,
                is_important: asset.data.is_important,
                id: None,
                // id: Some(id.clone()),
                spawners: vec![],
            });
            break;
        }

        UpdateParticleSystems {
            update_type: UpdateType::Init,
            systems,
            removed_systems: Vec::new()
        }
    }
}