use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::FixedOption;
use protocol::packets::assets::item_animations::{CameraSettingsPacket, ItemAnimationPacket, ItemPlayerAnimationsPacket, ItemPullbackConfigPacket, UpdateItemPlayerAnimations, WiggleWeightsPacket};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ItemAnimations {
    pub id: String,
    pub parent: Option<String>,
    pub animations: HashMap<String, ItemAnimationPacket>,
    pub wiggle_weights: WiggleWeightsPacket,
    pub camera: Option<CameraSettingsPacket>,
    pub pullback_config: Option<ItemPullbackConfigPacket>,
    pub use_first_person_override: bool,
}

impl AssetType for ItemAnimations {
    type InitPacketType = UpdateItemPlayerAnimations;

    fn name() -> &'static str {
        "ItemAnimations"
    }

    fn path() -> &'static str {
        "Item/Animations"
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
        let mut item_player_animations = HashMap::new();

        for (id, asset) in map.iter() {
            item_player_animations.insert(id.clone(), ItemPlayerAnimationsPacket {
                wiggle_weights: Default::default(),
                pullback_config: Default::default(),
                use_first_person_override: false,
                id: Some(asset.data.id.clone()),
                animations: Default::default(),
                camera: None,
            });
            break;
        }

        UpdateItemPlayerAnimations {
            update_type: UpdateType::Init,
            item_player_animations
        }
    }
}