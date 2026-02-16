use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::VarList;
use protocol::objects::HitBox;
use protocol::packets::assets::block_breaking_decals::{BlockBreakingDecalPacket, UpdateBlockBreakingDecals};
use protocol::packets::assets::block_hitbox::UpdateBlockHitBoxes;
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockBreakingDecal {
    pub id: String,
    pub parent: Option<String>,
    pub stage_textures: Vec<String>
}

impl AssetType for BlockBreakingDecal {
    type InitPacketType = UpdateBlockBreakingDecals;

    fn name() -> &'static str {
        "BlockBreakingDecals"
    }

    fn path() -> &'static str {
        "Item/Block/BreakingDecals"
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
        let mut block_breaking_decals: HashMap<String, BlockBreakingDecalPacket> = HashMap::new();

        if let Some((id, asset)) = map.iter().next() {
            block_breaking_decals.insert(id.to_owned(), BlockBreakingDecalPacket {
                stage_textures: asset.data.stage_textures.clone()
            });
        }

        UpdateBlockBreakingDecals {
            update_type: UpdateType::Init,
            block_breaking_decals,
        }
    }
}
