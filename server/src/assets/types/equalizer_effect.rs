use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::equalizer_effect::{EqualizerEffectPacket, UpdateEqualizerEffects};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct EqualizerEffect {
    pub id: String,
    pub parent: Option<String>,
    pub low_gain: f32,
    pub low_cut_off: f32,
    pub low_mid_gain: f32,
    pub low_mid_center: f32,
    pub low_mid_width: f32,
    pub high_mid_gain: f32,
    pub high_mid_center: f32,
    pub high_mid_width: f32,
    pub high_gain: f32,
    pub high_cut_off: f32,
}

impl Default for EqualizerEffect {
    fn default() -> Self {
        Self {
            id: String::new(),
            parent: None,
            low_gain: 1.0,
            low_cut_off: 200.0,
            low_mid_gain: 1.0,
            low_mid_center: 500.0,
            low_mid_width: 1.0,
            high_mid_gain: 1.0,
            high_mid_center: 3000.0,
            high_mid_width: 1.0,
            high_gain: 1.0,
            high_cut_off: 6000.0,
        }
    }
}

impl AssetType for EqualizerEffect {
    type InitPacketType = UpdateEqualizerEffects;

    fn name() -> &'static str {
        "EqualizerEffects"
    }

    fn path() -> &'static str {
        "Audio/EQ"
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
        let mut effects: HashMap<i32, EqualizerEffectPacket> = HashMap::new();

        if let Some((id, asset)) = map.iter().next() {
            effects.insert(0, EqualizerEffectPacket {
                low_gain: asset.data.low_gain,
                low_cut_off: asset.data.low_cut_off,
                low_mid_gain: asset.data.low_mid_gain,
                low_mid_center: asset.data.low_mid_center,
                low_mid_width: asset.data.low_mid_width,
                high_mid_gain: asset.data.high_mid_gain,
                high_mid_center: asset.data.high_mid_center,
                high_mid_width: asset.data.high_mid_width,
                high_gain: asset.data.high_gain,
                high_cut_off: asset.data.high_cut_off,
                id: Some(id.to_owned()),
            });
        }

        UpdateEqualizerEffects {
            update_type: UpdateType::Init,
            max_id: effects.len() as i32,
            effects,
        }
    }
}
