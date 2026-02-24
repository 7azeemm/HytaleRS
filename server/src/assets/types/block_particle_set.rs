use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde::de::{MapAccess, Visitor};
use protocol::objects::objects::{Color, Direction, Vec3f};
use protocol::packets::assets::block_particle_set::{BlockParticleEvent, BlockParticleSetPacket, UpdateBlockParticleSets};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockParticleSet {
    pub id: String,
    pub parent: Option<String>,
    pub color: Option<Color>,
    pub scale: f32,
    pub position_offset: Option<Vec3f>,
    pub rotation_offset: Option<Direction>,
    pub particles: HashMap<BlockParticleEvent, String>
}

impl Default for BlockParticleSet {
    fn default() -> Self {
        Self {
            id: String::default(),
            parent: None,
            color: None,
            scale: 1.0,
            position_offset: None,
            rotation_offset: None,
            particles: HashMap::new(),
        }
    }
}

impl AssetType for BlockParticleSet {
    type InitPacketType = UpdateBlockParticleSets;

    fn name() -> &'static str {
        "BlockParticleSets"
    }

    fn path() -> &'static str {
        "Item/Block/Particles"
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
        let mut block_particle_sets = HashMap::new();

        for (id, asset) in map.iter() {
            let data = &asset.data;
            let packet = BlockParticleSetPacket {
                color: data.color.clone().into(),
                scale: data.scale,
                position_offset: data.position_offset.clone().into(),
                rotation_offset: data.rotation_offset.clone().into(),
                id: Some(data.id.clone()),
                particles: data.particles.clone(),
            };

            block_particle_sets.insert(id.to_owned(), packet);
        }

        UpdateBlockParticleSets {
            update_type: UpdateType::Init,
            block_particle_sets,
        }
    }
}