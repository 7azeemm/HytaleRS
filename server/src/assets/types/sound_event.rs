use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::sound_event::{RandomSettingsPacket, SoundEventLayerPacket, SoundEventPacket, UpdateSoundEvents};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SoundEvent {
    pub id: String,
    pub parent: Option<String>,
    pub volume: f32,
    pub pitch: f32,
    pub music_ducking_volume: f32,
    pub ambient_ducking_volume: f32,
    pub start_attenuation_distance: f32,
    pub max_distance: f32,
    pub max_instance: i32,
    pub prevent_sound_interruption: bool,
    pub layers: Vec<SoundEventLayer>,
    pub audio_category: Option<String>,
}

impl Default for SoundEvent {
    fn default() -> Self {
        Self {
            id: String::new(),
            parent: None,
            volume: 1.0,
            pitch: 1.0,
            music_ducking_volume: 1.0,
            ambient_ducking_volume: 1.0,
            start_attenuation_distance: 2.0,
            max_distance: 16.0,
            max_instance: 50,
            prevent_sound_interruption: false,
            layers: Vec::new(),
            audio_category: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SoundEventLayer {
    pub volume: f32,
    pub start_delay: f32,
    pub looping: bool,
    pub probability: i32,
    pub probability_reroll_delay: f32,
    pub random_settings: RandomSettings,
    pub files: Vec<String>,
    pub round_robin_history_size: i32,
}

impl Default for SoundEventLayer {
    fn default() -> Self {
        Self {
            volume: 1.0,
            start_delay: 0.0,
            looping: false,
            probability: 100,
            probability_reroll_delay: 1.0,
            random_settings: RandomSettings::default(),
            files: Vec::new(),
            round_robin_history_size: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RandomSettings {
    pub min_volume: f32,
    pub max_volume: f32,
    pub min_pitch: f32,
    pub max_pitch: f32,
    pub max_start_offset: f32,
}

impl Default for RandomSettings {
    fn default() -> Self {
        Self {
            min_volume: 1.0,
            max_volume: 1.0,
            min_pitch: 1.0,
            max_pitch: 1.0,
            max_start_offset: 0.0,
        }
    }
}

impl AssetType for SoundEvent {
    type InitPacketType = UpdateSoundEvents;

    fn name() -> &'static str {
        "SoundEvents"
    }

    fn path() -> &'static str {
        "Audio/SoundEvents"
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
        let mut sound_events: HashMap<i32, SoundEventPacket> = HashMap::new();

        if let Some((id, asset)) = map.iter().next() {
            sound_events.insert(0, SoundEventPacket {
                id: Some(id.to_owned()),
                volume: asset.data.volume,
                pitch: asset.data.pitch,
                music_ducking_volume: asset.data.music_ducking_volume,
                ambient_ducking_volume: asset.data.ambient_ducking_volume,
                max_instance: asset.data.max_instance,
                prevent_sound_interruption: asset.data.prevent_sound_interruption,
                start_attenuation_distance: asset.data.start_attenuation_distance,
                max_distance: asset.data.max_distance,
                audio_category: 0, // Fixme
                layers: asset.data.layers.iter().map(|l| SoundEventLayerPacket {
                    volume: l.volume,
                    start_delay: l.start_delay,
                    looping: l.looping,
                    probability: l.probability,
                    probability_reroll_delay: l.probability_reroll_delay,
                    round_robin_history_size: l.round_robin_history_size,
                    random_settings: Some(RandomSettingsPacket {
                        min_volume: l.random_settings.min_volume,
                        max_volume: l.random_settings.max_volume,
                        min_pitch: l.random_settings.min_pitch,
                        max_pitch: l.random_settings.max_pitch,
                        max_start_offset: l.random_settings.max_start_offset
                    }),
                    files: l.files.clone()
                }).collect(),
            });
        }

        UpdateSoundEvents {
            update_type: UpdateType::Init,
            max_id: sound_events.len() as i32,
            sound_events,
        }
    }
}
