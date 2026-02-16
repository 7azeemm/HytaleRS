use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::sound_set::{SoundCategory, SoundSetPacket, UpdateSoundSets};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SoundSet {
    pub id: String,
    pub parent: Option<String>,
    pub sound_events: HashMap<String, String>,
    pub category: SoundCategory
}

impl Default for SoundSet {
    fn default() -> Self {
        Self {
            id: String::new(),
            parent: None,
            sound_events: HashMap::default(),
            category: SoundCategory::SFX
        }
    }
}

impl AssetType for SoundSet {
    type InitPacketType = UpdateSoundSets;

    fn name() -> &'static str {
        "SoundSets"
    }

    fn path() -> &'static str {
        "Audio/SoundSets"
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
        let mut sound_sets: HashMap<i32, SoundSetPacket> = HashMap::new();

        if let Some((id, asset)) = map.iter().next() {
            sound_sets.insert(0, SoundSetPacket {
                id: Some(id.to_owned()),
                category: asset.data.category,
                sounds: HashMap::default()
            });
        }

        UpdateSoundSets {
            update_type: UpdateType::Init,
            max_id: sound_sets.len() as i32,
            sound_sets,
        }
    }
}
