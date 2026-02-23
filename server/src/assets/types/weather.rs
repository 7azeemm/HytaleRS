use std::collections::HashMap;
use log::info;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::{FixedOption, PacketCodec};
use protocol::io::encoder::Encoder;
use protocol::io::packet::Packet;
use protocol::packets::assets::update_type::UpdateType;
use protocol::packets::assets::weather::{FogOptionsPacket, NearFogPacket, UpdateWeathers, WeatherPacket};
use crate::assets::asset_type::{Asset, AssetType};
use crate::assets::objects::{TimeColor, TimeColorAlpha, TimeFloat};
use crate::net::utils::packet_io::read_packet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Weather {
    pub id: String,
    pub parent: Option<String>,
    pub stars: String,
    pub screen_effect: String,
    pub fog_distance: Vec<f32>,
    pub fog_options: Option<FogOptions>,
    pub particle: Option<WeatherParticle>,
    pub screen_effect_colors: Vec<TimeColorAlpha>,
    pub sunlight_damping_multiplier: Vec<TimeFloat>,
    pub sunlight_colors: Vec<TimeColor>,
    pub sun_colors: Vec<TimeColor>,
    pub moon_colors: Vec<TimeColorAlpha>,
    pub sun_glow_colors: Vec<TimeColorAlpha>,
    pub moon_glow_colors: Vec<TimeColorAlpha>,
    pub sun_scales: Vec<TimeFloat>,
    pub moon_scales: Vec<TimeFloat>,
    pub sky_top_colors: Vec<TimeColorAlpha>,
    pub sky_bottom_colors: Option<Vec<TimeColorAlpha>>,//FIXME: make null value empty vec in custom deserializer
    pub sky_sunset_colors: Vec<TimeColorAlpha>,
    pub fog_colors: Vec<TimeColor>,
    pub fog_height_fall_offs: Vec<TimeFloat>,
    pub fog_densities: Vec<TimeFloat>,
    pub water_tints: Vec<TimeColor>,
    pub color_filters: Vec<TimeColor>,
    pub moons: Vec<DayTexture>,
    pub clouds: Vec<Cloud>,
}

impl Default for Weather {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            parent: None,
            stars: "".to_string(),
            screen_effect: "".to_string(),
            fog_distance: vec![-96.0, 1024.0],
            fog_options: None,
            particle: None,
            screen_effect_colors: vec![],
            sunlight_damping_multiplier: vec![],
            sunlight_colors: vec![],
            sun_colors: vec![],
            moon_colors: vec![],
            sun_glow_colors: vec![],
            moon_glow_colors: vec![],
            sun_scales: vec![],
            moon_scales: vec![],
            sky_top_colors: vec![],
            sky_bottom_colors: None,
            sky_sunset_colors: vec![],
            fog_colors: vec![],
            fog_height_fall_offs: vec![],
            fog_densities: vec![],
            water_tints: vec![],
            color_filters: vec![],
            moons: vec![],
            clouds: vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct DayTexture {
    pub day: i32,
    pub texture: String
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Cloud {
    pub texture: String,
    pub colors: Vec<TimeColorAlpha>,
    pub speeds: Vec<TimeFloat>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct FogOptions {
    pub ignore_fog_limits: bool,
    pub effective_view_distance_multiplier: f32,
    pub fog_height_camera_fixed: Option<f32>,
    pub fog_height_camera_offset: f32,
}

impl Default for FogOptions {
    fn default() -> Self {
        Self {
            ignore_fog_limits: false,
            effective_view_distance_multiplier: 1.0,
            fog_height_camera_fixed: None,
            fog_height_camera_offset: 0.0
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct WeatherParticle {
    pub system_id: Option<String>,
    pub color: Option<String>,//FIXME: `Option<Color>`
    pub scale: f32,
    pub overground_only: bool,
    pub position_offset_multiplier: f32,
}

impl AssetType for Weather {
    type InitPacketType = UpdateWeathers;

    fn name() -> &'static str {
        "Weathers"
    }

    fn path() -> &'static str {
        "Weathers"
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
        let mut weathers = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            let data = &asset.data;
            let packet = WeatherPacket {
                fog: FixedOption(NearFogPacket {
                    near: data.fog_distance[0],//TODO: panics
                    far: data.fog_distance[1],
                }.into()),
                fog_options: FixedOption(FogOptionsPacket {
                    ignore_fog_limits: true,
                    effective_view_distance_multiplier: 1.0,
                    fog_far_view_distance: 1.0,
                    fog_height_camera_offset: 4.0,
                    fog_height_camera_overridden: true,
                    fog_height_camera_fixed: 5.0
                }.into()),
                id: Some(id.clone()),
                tag_indexes: vec![0, 5],
                stars: Some(data.stars.clone()),
                moons: Default::default(),
                clouds: vec![],
                sunlight_damping_multiplier: Default::default(),
                sunlight_colors: Default::default(),
                sky_top_colors: Default::default(),
                sky_bottom_colors: Default::default(),
                sky_sunset_colors: Default::default(),
                sun_colors: Default::default(),
                sun_scales: Default::default(),
                sun_glow_colors: Default::default(),
                moon_colors: Default::default(),
                moon_scales: Default::default(),
                moon_glow_colors: Default::default(),
                fog_colors: Default::default(),
                fog_height_fall_offs: Default::default(),
                fog_densities: Default::default(),
                screen_effect: Some(data.screen_effect.clone()),
                screen_effect_colors: Default::default(),
                color_filters: Default::default(),
                water_tints: Default::default(),
                weather_particle: None,
            };

            weathers.insert(i as i32, packet);

            break;
        }

        let packet = UpdateWeathers {
            update_type: UpdateType::Init,
            max_id: weathers.len() as i32,
            weathers
        };

        let bytes = Packet::encode(&packet).unwrap();
        let packet: UpdateWeathers = Packet::decode(&bytes).unwrap();

        packet
    }
}