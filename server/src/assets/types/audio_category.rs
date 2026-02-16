use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::audio_category::{AudioCategoryPacket, UpdateAudioCategories};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct AudioCategory {
    pub id: String,
    pub parent: Option<String>,
    pub volume: f32
}

impl AssetType for AudioCategory {
    type InitPacketType = UpdateAudioCategories;

    fn name() -> &'static str {
        "AudioCategories"
    }

    fn path() -> &'static str {
        "Audio/AudioCategories"
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
        let mut categories: HashMap<i32, AudioCategoryPacket> = HashMap::new();

        if let Some((id, asset)) = map.iter().next() {
            categories.insert(0, AudioCategoryPacket {
                volume: asset.data.volume,
                id: Some(id.to_owned()),
            });
        }

        UpdateAudioCategories {
            update_type: UpdateType::Init,
            max_id: categories.len() as i32,
            categories,
        }
    }
}
