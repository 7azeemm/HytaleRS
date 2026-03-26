use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::VarList;
use protocol::objects::objects::HitBox;
use protocol::packets::assets::block_hitbox::UpdateBlockHitBoxes;
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockHitBox {
    pub id: String,
    pub parent: Option<String>,
    pub boxes: Vec<HitBox>,
}

impl AssetType for BlockHitBox {
    type InitPacketType = UpdateBlockHitBoxes;

    fn name() -> &'static str {
        "BlockHitboxes"
    }

    fn path() -> &'static str {
        "Item/Block/Hitboxes"
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
        map: RwLockReadGuard<RawRwLock, HashMap<String, Asset<Self>>>,
    ) -> Self::InitPacketType {
        let mut block_hitboxes: HashMap<i32, VarList<HitBox, _>> = HashMap::new();

        if let Some(asset) = map.values().next() {
            block_hitboxes.insert(0, asset.data.boxes.clone().into());
        }

        UpdateBlockHitBoxes {
            update_type: UpdateType::Init,
            max_id: block_hitboxes.len() as i32,
            block_hitboxes,
        }
    }
}
