use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::interaction_type::InteractionType;
use protocol::packets::assets::unarmed_interaction::UpdateUnarmedInteractions;
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct UnarmedInteraction {
    pub id: String,
    pub parent: Option<String>,
    pub interactions: HashMap<InteractionType, String>,
}

impl AssetType for UnarmedInteraction {
    type InitPacketType = UpdateUnarmedInteractions;

    fn name() -> &'static str {
        "UnarmedInteractions"
    }

    fn path() -> &'static str {
        "Item/Unarmed/Interactions"
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

        interactions.insert(InteractionType::Equipped, 0);

        UpdateUnarmedInteractions {
            update_type: UpdateType::Init,
            interactions,
        }
    }
}
