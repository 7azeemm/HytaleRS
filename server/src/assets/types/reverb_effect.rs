use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::equalizer_effect::{EqualizerEffectPacket, UpdateEqualizerEffects};
use protocol::packets::assets::reverb_effect::{ReverbEffectPacket, UpdateReverbEffects};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ReverbEffect {
    pub id: String,
    pub parent: Option<String>,
    pub dry_gain: f32,
    pub modal_density: f32,
    pub diffusion: f32,
    pub gain: f32,
    pub high_frequency_gain: f32,
    pub decay_time: f32,
    pub high_frequency_decay_ratio: f32,
    pub reflection_gain: f32,
    pub reflection_delay: f32,
    pub late_reverb_gain: f32,
    pub late_reverb_delay: f32,
    pub room_roll_off_factor: f32,
    pub air_absorption_high_frequency_gain: f32,
    pub limit_decay_high_frequency: bool,
}

impl Default for ReverbEffect {
    fn default() -> Self {
        // Fixme: wrong
        Self {
            id: String::new(),
            parent: None,
            dry_gain: 0.0,
            modal_density: 1.0,
            diffusion: 1.0,
            gain: -10.0,
            high_frequency_gain: -1.0,
            decay_time: 1.49,
            high_frequency_decay_ratio: 0.83,
            reflection_gain: -26.0,
            reflection_delay: 0.007,
            late_reverb_gain: 2.0,
            late_reverb_delay: 0.011,
            room_roll_off_factor: 0.0,
            air_absorption_high_frequency_gain: -0.05,
            limit_decay_high_frequency: false,
        }
    }
}

impl AssetType for ReverbEffect {
    type InitPacketType = UpdateReverbEffects;

    fn name() -> &'static str {
        "ReverbEffects"
    }

    fn path() -> &'static str {
        "Audio/Reverb"
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
        let mut effects: HashMap<i32, ReverbEffectPacket> = HashMap::new();

        if let Some((id, asset)) = map.iter().next() {
            effects.insert(0, ReverbEffectPacket {
                dry_gain: asset.data.dry_gain,
                modal_density: asset.data.modal_density,
                diffusion: asset.data.diffusion,
                gain: asset.data.gain,
                high_frequency_gain: asset.data.high_frequency_gain,
                decay_time: asset.data.decay_time,
                high_frequency_decay_ratio: asset.data.high_frequency_decay_ratio,
                reflection_gain: asset.data.reflection_gain,
                reflection_delay: asset.data.reflection_delay,
                late_reverb_gain: asset.data.late_reverb_gain,
                late_reverb_delay: asset.data.late_reverb_delay,
                room_roll_off_factor: asset.data.room_roll_off_factor,
                air_absorption_high_frequency_gain: asset.data.air_absorption_high_frequency_gain,
                limit_decay_high_frequency: asset.data.limit_decay_high_frequency,
                id: Some(id.to_owned()),
            });
        }

        UpdateReverbEffects {
            update_type: UpdateType::Init,
            max_id: effects.len() as i32,
            effects,
        }
    }
}
