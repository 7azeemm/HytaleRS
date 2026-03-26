use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::objects::objects::{Direction, RangeFloat, RangeVec3f, Vec3f};
use protocol::packets::assets::particle_spawner::{InitialVelocity, ParticleAttractorPacket};
use protocol::packets::assets::particle_system::{ParticleSpawnerGroupPacket, ParticleSystemPacket, UpdateParticleSystems};
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
            let spawners: Vec<ParticleSpawnerGroupPacket> = asset.data.spawners.iter()
                .map(|p| {
                    let attractors: Vec<ParticleAttractorPacket> = p.attractors.iter()
                        .map(|a| {
                            ParticleAttractorPacket {
                                position: a.position.clone().into(),
                                radial_axis: a.radial_axis.clone().into(),
                                trail_position_multiplier: a.trail_position_multiplier,
                                radius: a.radius,
                                radial_acceleration: a.radial_acceleration,
                                radial_tangent_acceleration: a.radial_tangent_acceleration,
                                linear_acceleration: a.linear_acceleration.clone().into(),
                                radial_impulse: a.radial_impulse,
                                radial_tangent_impulse: a.radial_tangent_impulse,
                                linear_impulse: a.linear_impulse.clone().into(),
                                damping_multiplier: a.damping_multiplier.clone().into(),
                            }
                        })
                        .collect();
                    ParticleSpawnerGroupPacket {
                        position_offset: p.position_offset.clone().into(),
                        rotation_offset: p.rotation_offset.clone().into(),
                        fixed_rotation: p.fixed_rotation,
                        start_delay: p.start_delay,
                        spawn_rate: p.spawn_rate.clone().into(),
                        wave_delay: p.wave_delay.clone().into(),
                        total_spawners: p.total_spawners,
                        max_concurrent: p.max_concurrent,
                        initial_velocity: p.initial_velocity.clone().into(),
                        emit_offset: p.emit_offset.clone().into(),
                        life_span: p.life_span.clone().into(),
                        spawner_id: p.spawner_id.clone().into(),
                        attractors,
                    }
                })
                .collect();

            systems.insert(id.clone(), ParticleSystemPacket {
                life_span: asset.data.life_span,
                cull_distance: asset.data.cull_distance,
                bounding_radius: asset.data.bounding_radius,
                is_important: asset.data.is_important,
                id: Some(id.clone()),
                spawners,
            });
        }

        UpdateParticleSystems {
            update_type: UpdateType::Init,
            systems,
            removed_systems: Vec::new()
        }
    }
}