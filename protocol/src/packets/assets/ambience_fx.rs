use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::{Range, RangeByte, RangeFloat};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 62, max_size = 0x64000000, compressed)]
pub struct UpdateAmbienceFX {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub ambience_fx: HashMap<i32, AmbienceFXPacket>,
}

#[packet_field]
pub struct AmbienceFXPacket {
    pub sound_effect: FixedOption<AmbienceFXSoundEffectPacket>,
    pub priority: i32,
    pub audio_category_index: i32,
    pub id: Option<String>,
    pub conditions: Option<AmbienceFXConditionsPacket>,
    pub sounds: Vec<AmbienceFXSoundPacket>,
    pub music: Option<AmbienceFXMusicPacket>,
    pub ambient_bed: Option<AmbienceFXAmbientBedPacket>,
    pub blocked_ambience_fx_indices: Vec<i32>,
}

#[packet_field]
pub struct AmbienceFXConditionsPacket {
    pub never: bool,
    pub environment_tag_pattern_index: i32,
    pub weather_tag_pattern_index: i32,
    pub altitude: FixedOption<Range>,
    pub walls: FixedOption<RangeByte>,
    pub roof: bool,
    pub roof_material_tag_pattern_index: i32,
    pub floor: bool,
    pub sun_light_level: FixedOption<RangeByte>,
    pub torch_light_level: FixedOption<RangeByte>,
    pub global_light_level: FixedOption<RangeByte>,
    pub day_time: FixedOption<RangeFloat>,
    pub environment_indices: Vec<i32>,
    pub weather_indices: Vec<i32>,
    pub fluid_fx_indices: Vec<i32>,
    pub surrounding_block_sound_sets: Vec<AmbienceFXBlockSoundSetPacket>,
}

#[packet_field]
pub struct AmbienceFXBlockSoundSetPacket {
    pub block_sound_set_index: i32,
    pub percent: FixedOption<RangeFloat>
}

#[packet_field]
pub struct AmbienceFXSoundPacket {
    pub sound_event_index: i32,
    pub play_3d: AmbienceFXSoundPlay3D,
    pub block_sound_set_index: i32,
    pub altitude: AmbienceFXAltitude,
    pub frequency: FixedOption<RangeFloat>,
    pub radius: FixedOption<Range>
}

#[packet_field]
pub struct AmbienceFXSoundEffectPacket {
    pub reverb_effect_index: i32,
    pub equalizer_effect_index: i32,
    pub is_instant: bool
}

#[packet_field]
pub struct AmbienceFXMusicPacket {
    pub volume: f32,
    pub tracks: Vec<String>
}

#[packet_field]
pub struct AmbienceFXAmbientBedPacket {
    pub volume: f32,
    pub transition_speed: AmbienceTransitionSpeed,
    pub track: Option<String>,
}

#[packet_enum]
pub enum AmbienceFXSoundPlay3D {
    Random,
    LocationName,
    No
}

#[packet_enum]
pub enum AmbienceFXAltitude {
    Normal,
    Lowest,
    Highest,
    Random
}

#[packet_enum]
pub enum AmbienceTransitionSpeed {
    Default,
    Fast,
    Instant
}