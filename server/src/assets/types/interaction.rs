use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::interactions::interaction::{InteractionPacket, UpdateInteractions, WaitForDataFrom};
use protocol::packets::assets::interactions::simple_block_interaction::SimpleBlockInteraction;
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Interaction {
    pub id: String,
    pub parent: Option<String>,
}

impl AssetType for Interaction {
    type InitPacketType = UpdateInteractions;

    fn name() -> &'static str {
        "Interactions"
    }

    fn path() -> &'static str {
        "Item/Interactions"
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
            interactions.insert(i as i32, InteractionPacket {
                packet: Box::new(SimpleBlockInteraction {
                    wait_for_data_from: WaitForDataFrom::Client,
                    horizontal_speed_multiplier: 0.0,
                    run_time: 0.0,
                    cancel_on_item_change: false,
                    next: 0,
                    failed: 0,
                    use_latest_target: false,
                    effects: None,
                    settings: Default::default(),
                    rules: None,
                    tags: vec![],
                    camera: None,
                }),
            });
            break;
        }

        UpdateInteractions {
            update_type: UpdateType::Init,
            max_id: interactions.len() as i32,
            interactions,
        }
    }
}
