use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::item_sound_set::{ItemSoundEvent, ItemSoundSetPacket, UpdateItemSoundSets};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ItemSoundSet {
    pub id: String,
    pub parent: Option<String>,
    pub sound_events: HashMap<ItemSoundEvent, String>,
}

impl AssetType for ItemSoundSet {
    type InitPacketType = UpdateItemSoundSets;

    fn name() -> &'static str {
        "ItemSounds"
    }

    fn path() -> &'static str {
        "Audio/ItemSounds"
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
        let mut item_sound_sets: HashMap<i32, ItemSoundSetPacket> = HashMap::new();

        if let Some((id, _)) = map.iter().next() {
            item_sound_sets.insert(0, ItemSoundSetPacket {
                id: Some(id.to_owned()),
                sound_event_indices: HashMap::default(),
            });
        }

        UpdateItemSoundSets {
            update_type: UpdateType::Init,
            max_id: item_sound_sets.len() as i32,
            item_sound_sets,
        }
    }
}
