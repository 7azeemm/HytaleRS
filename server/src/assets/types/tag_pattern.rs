use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::tag_pattern::{TagPatternPacket, TagPatternType, UpdateTagPatterns};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

//FIXME: Abstract

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct TagPattern {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for TagPattern {
    type InitPacketType = UpdateTagPatterns;

    fn name() -> &'static str {
        "TagPatterns"
    }

    fn path() -> &'static str {
        "TagPatterns"
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
        let mut patterns = HashMap::new();

        for (i, (_, asset)) in map.iter().enumerate() {
            patterns.insert(i as i32, TagPatternPacket {
                tag_type: TagPatternType::Equals,
                tag_index: i as i32,
                operands: vec![],
                not: None,
            });
        }

        UpdateTagPatterns {
            update_type: UpdateType::Init,
            max_id: map.len() as i32,
            patterns
        }
    }
}