use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::FixedOption;
use protocol::objects::objects::{Range, RangeByte, RangeFloat};
use protocol::packets::assets::ambience_fx::{AmbienceFXAltitude, AmbienceFXPacket, AmbienceFXSoundPlay3D, AmbienceTransitionSpeed, UpdateAmbienceFX};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct AmbienceFX {
    pub id: String,
    pub parent: Option<String>,
    pub conditions: Option<AmbienceFXConditions>,
    pub sounds: Vec<AmbienceFXSound>,
    pub music: Option<AmbienceFXMusic>,
    pub ambient_bed: Option<AmbienceFXAmbientBed>,
    pub sound_effect: Option<AmbienceFXSoundEffect>,
    pub priority: i32,
    pub blocked_ambience_fx_ids: Vec<String>,
    pub audio_category: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct AmbienceFXConditions {
    pub parent: Option<String>,
    pub never: bool,
    pub environment_ids: Vec<String>,
    // pub environment_tag_pattern: HashMap<String, String>,
    pub weather_ids: Vec<String>,
    // pub weather_tag_pattern: HashMap<String, String>,
    #[serde(rename = "FluidFXIds")]
    pub fluid_fx_ids: Vec<String>,
    pub surrounding_block_sound_sets: Vec<AmbienceFXBlockSoundSet>,
    pub altitude: Range,
    pub walls: RangeByte,
    pub roof: bool,
    // pub roof_material_tag_pattern: HashMap<String, String>,
    pub floor: bool,
    pub sun_light_level: RangeByte,
    pub torch_light_level: RangeByte,
    pub global_light_level: RangeByte,
    pub day_time: RangeFloat,
}

impl Default for AmbienceFXConditions {
    fn default() -> Self {
        Self {
            parent: None,
            never: false,
            environment_ids: Vec::new(),
            // environment_tag_pattern: HashMap::default(),
            weather_ids: Vec::new(),
            // weather_tag_pattern: HashMap::default(),
            fluid_fx_ids: Vec::new(),
            surrounding_block_sound_sets: Vec::new(),
            altitude: Range { min: 0, max: 512 },
            walls: RangeByte { min: 0, max: 4 },
            roof: false,
            // roof_material_tag_pattern: HashMap::default(),
            floor: false,
            sun_light_level: RangeByte { min: 0, max: 15 },
            torch_light_level: RangeByte { min: 0, max: 15 },
            global_light_level: RangeByte { min: 0, max: 15 },
            day_time: RangeFloat { min: 0.0, max: 24.0 },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct AmbienceFXBlockSoundSet {
    pub block_sound_set_id: String,
    pub percent: Option<RangeFloat>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct AmbienceFXSound {
    pub sound_event_id: String,
    #[serde(rename = "Play3D")]
    pub play_3d: AmbienceFXSoundPlay3D,
    pub block_sound_set_id: String,
    pub altitude: AmbienceFXAltitude,
    pub frequency: RangeFloat,
    pub radius: Range
}

impl Default for AmbienceFXSound {
    fn default() -> Self {
        Self {
            sound_event_id: String::new(),//Fixme: impl custom Default thing, some fields are not supposed to have default
            play_3d: AmbienceFXSoundPlay3D::Random,
            block_sound_set_id: String::new(),
            altitude: AmbienceFXAltitude::Normal,
            frequency: RangeFloat { min: 1.0, max: 10.0 },
            radius: Range { min: 0, max: 24 },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct AmbienceFXMusic {
    pub tracks: Vec<String>,
    pub volume: f32,//FIXME: Wrong
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct AmbienceFXAmbientBed {
    pub track: Option<String>,
    pub volume: f32,//FIXME: Wrong
    pub transition_speed: AmbienceTransitionSpeed,
}

impl Default for AmbienceFXAmbientBed {
    fn default() -> Self {
        Self {
            track: None,
            volume: 0.0,
            transition_speed: AmbienceTransitionSpeed::Default
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct AmbienceFXSoundEffect {
    pub reverb_effect_id: Option<String>,
    pub equalizer_effect_id: Option<String>,
    pub is_instant: bool
}

impl AssetType for AmbienceFX {
    type InitPacketType = UpdateAmbienceFX;

    fn name() -> &'static str {
        "AmbienceFX"
    }

    fn path() -> &'static str {
        "Audio/AmbienceFX"
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
        let mut ambience_fx = HashMap::new();

        for (i, (id, _)) in map.iter().enumerate() {
            ambience_fx.insert(i as i32, AmbienceFXPacket {
                sound_effect: FixedOption(None),
                priority: 0,
                audio_category_index: 0,
                id: Some(id.to_owned()),
                conditions: None,
                sounds: vec![],
                music: None,
                ambient_bed: None,
                blocked_ambience_fx_indices: vec![],
            });
        }

        UpdateAmbienceFX {
            update_type: UpdateType::Init,
            max_id: ambience_fx.len() as i32,
            ambience_fx
        }
    }
}