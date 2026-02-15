use crate::assets::asset_type::{Asset, AssetType};
use parking_lot::RawRwLock;
use parking_lot::lock_api::RwLockReadGuard;
use protocol::packets::assets::block_sets::{BlockSetPacket, UpdateBlockSets};
use protocol::packets::assets::update_type::UpdateType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockSet {
    pub id: String,
    pub parent: Option<String>,
    pub include_all: bool,
    pub include_block_types: Vec<String>,
    pub exclude_block_types: Vec<String>,
    pub include_block_groups: Vec<String>,
    pub exclude_block_groups: Vec<String>,
    pub include_hitbox_types: Vec<String>,
    pub exclude_hitbox_types: Vec<String>,
    pub include_categories: Vec<Vec<String>>,
    pub exclude_categories: Vec<Vec<String>>,
}

impl AssetType for BlockSet {
    type InitPacketType = UpdateBlockSets;

    fn name() -> &'static str {
        "BlockSets"
    }

    fn path() -> &'static str {
        "Item/Block/Sets"
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
        let mut block_sets = HashMap::new();

        for id in map.keys() {
            let packet = BlockSetPacket {
                name: Some(id.to_owned()),
                blocks: vec![5, 8, 10].into(),
            };

            block_sets.insert(id.to_owned(), packet);
        }

        UpdateBlockSets {
            update_type: UpdateType::Init,
            block_sets,
        }
    }
}
