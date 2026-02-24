use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::VarList;
use protocol::objects::objects::{FloatRange, HitBox};
use protocol::packets::assets::block_hitbox::UpdateBlockHitBoxes;
use protocol::packets::assets::block_sound_set::{BlockSoundEvent, BlockSoundSetPacket, UpdateBlockSoundSets};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockSoundSet {
    pub id: String,
    pub parent: Option<String>,
    pub sound_events: HashMap<BlockSoundEvent, String>,
    pub move_in_repeat_range: FloatRange
}

impl Default for BlockSoundSet {
    fn default() -> Self {
        Self {
            id: String::new(),
            parent: None,
            sound_events: HashMap::default(),
            move_in_repeat_range: FloatRange::new(0.5, 1.5)
        }
    }
}

impl AssetType for BlockSoundSet {
    type InitPacketType = UpdateBlockSoundSets;

    fn name() -> &'static str {
        "BlockSoundSets"
    }

    fn path() -> &'static str {
        "Item/Block/Sounds"
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
        let mut block_sound_sets: HashMap<i32, BlockSoundSetPacket> = HashMap::new();

        if let Some(asset) = map.values().next() {
            block_sound_sets.insert(0, BlockSoundSetPacket {
                move_in_repeat_range: Some(asset.data.move_in_repeat_range.clone()).into(),
                id: Some(asset.data.id.clone()),
                sound_event_indices: HashMap::default()
            });
        }

        UpdateBlockSoundSets {
            update_type: UpdateType::Init,
            max_id: block_sound_sets.len() as i32,
            block_sound_sets,
        }
    }
}
