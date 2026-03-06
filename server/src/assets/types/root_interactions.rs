use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::root_interactions::{RootInteractionPacket, UpdateRootInteractions};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct RootInteraction {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for RootInteraction {
    type InitPacketType = UpdateRootInteractions;

    fn name() -> &'static str {
        "RootInteractions"
    }

    fn path() -> &'static str {
        "Item/RootInteractions"
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
        let mut interactions = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            interactions.insert(i as i32, RootInteractionPacket {
                click_queuing_timeout: 0.0,
                require_new_click: false,
                id: Some(id.clone()),
                interactions: vec![],
                cooldown: None,
                settings: Default::default(),
                rules: None,
                tags: vec![],
            });
        }

        UpdateRootInteractions {
            update_type: UpdateType::Init,
            max_id: interactions.len() as i32,
            interactions,
        }
    }
}
