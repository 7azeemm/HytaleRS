use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::block_group::{BlockGroupPacket, UpdateBlockGroups};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockGroup {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for BlockGroup {
    type InitPacketType = UpdateBlockGroups;

    fn name() -> &'static str {
        "BlockGroups"
    }

    fn path() -> &'static str {
        "Item/Groups"
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
        let mut groups = HashMap::new();

        if let Some((id, asset)) = map.iter().next() {
            groups.insert(id.clone(), BlockGroupPacket {
                names: vec![]
            });
        }

        UpdateBlockGroups {
            update_type: UpdateType::Init,
            groups,
        }
    }
}
