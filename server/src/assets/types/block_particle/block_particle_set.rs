use std::any::TypeId;
use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::FixedOption;
use protocol::objects::{Color, Direction, Vec3f};
use protocol::packets::assets::block_particle_set::{BlockParticleEvent, BlockParticleSetPacket, UpdateBlockParticleSets};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};
use crate::assets::types::block_set::block_set::BlockSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockParticleSet {
    pub id: String,
    pub color: Option<Color>,
    pub scale: f32,
    pub position_offset: Option<Vec3f>,
    pub rotation_offset: Option<Direction>,
    pub particle_system_ids: HashMap<BlockParticleEvent, String>
}

impl Default for BlockParticleSet {
    fn default() -> Self {
        Self {
            id: String::default(),
            color: None,
            scale: 1.0,
            position_offset: None,
            rotation_offset: None,
            particle_system_ids: HashMap::new(),
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
                particle_system_ids: data.particle_system_ids.clone(),
            };

            block_particle_sets.insert(id.to_owned(), packet);
        }

        UpdateBlockParticleSets {
            update_type: UpdateType::Init,
            block_particle_sets,
        }
    }
}