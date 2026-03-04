use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::objects::objects::Color;
use protocol::packets::assets::item_quality::{ItemQualityPacket, UpdateItemQualities};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ItemQuality {
    pub id: String,
    pub parent: Option<String>,
    pub quality_value: i32,
    pub item_tooltip_texture: Option<String>,
    pub item_tooltip_arrow_texture: Option<String>,
    pub slot_texture: Option<String>,
    pub block_slot_texture: Option<String>,
    pub special_slot_texture: Option<String>,
    pub text_color: Option<String>,//Color
    pub localization_key: Option<String>,
    // pub item_entity_config
    pub visible_quality_label: bool,
    pub render_special_slot: bool,
    pub hide_from_search: bool,
}

impl AssetType for ItemQuality {
    type InitPacketType = UpdateItemQualities;

    fn name() -> &'static str {
        "ItemQualities"
    }

    fn path() -> &'static str {
        "Item/Qualities"
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
        let mut item_qualities = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            item_qualities.insert(i as i32, ItemQualityPacket {
                text_color: Default::default(),
                visible_quality_label: asset.data.visible_quality_label,
                render_special_slot: asset.data.render_special_slot,
                hide_from_search: asset.data.hide_from_search,
                id: Some(id.to_owned()),
                item_tooltip_texture: asset.data.item_tooltip_texture.clone(),
                item_tooltip_arrow_texture: asset.data.item_tooltip_arrow_texture.clone(),
                slot_texture: asset.data.slot_texture.clone(),
                block_slot_texture: asset.data.block_slot_texture.clone(),
                special_slot_texture: asset.data.special_slot_texture.clone(),
                localization_key: asset.data.localization_key.clone(),
            });
        }

        UpdateItemQualities {
            update_type: UpdateType::Init,
            max_id: item_qualities.len() as i32,
            item_qualities,
        }
    }
}
