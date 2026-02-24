use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::FixedOption;
use protocol::objects::objects::Color;
use protocol::packets::assets::ambience_fx::{AmbienceFXPacket, UpdateAmbienceFX};
use protocol::packets::assets::fluid_fx::{FluidFXMovementSettings, FluidFXPacket, FluidFog, UpdateFluidFX};
use protocol::packets::assets::shader_type::ShaderType;
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct FluidFX {
    pub id: String,
    pub parent: Option<String>,
    pub fog: FluidFog,
    pub fog_color: Color,
    pub fog_distance: Vec<f32>,
    pub fog_depth_start: f32,
    pub fog_depth_falloff: f32,
    pub colors_saturation: f32,
    pub colors_filter: Vec<f32>,
    pub distortion_amplitude: f32,
    pub distortion_frequency: f32,
    pub particle: Option<FluidParticle>,
    pub movement_settings: Option<FluidFXMovementSettings>
}

impl Default for FluidFX {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            parent: None,
            fog: FluidFog::Color,
            fog_color: Color { red: 255, green: 255, blue: 255 },
            fog_distance: vec![0.0, 32.0],
            fog_depth_start: 40.0,
            fog_depth_falloff: 10.0,
            colors_saturation: 1.0,
            colors_filter: vec![1.0, 1.0, 1.0],
            distortion_amplitude: 8.0,
            distortion_frequency: 4.0,
            particle: None,
            movement_settings: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct FluidParticle {
    pub system_id: String,
    pub color: String, // color
    pub scale: f32
}

impl Default for FluidParticle {
    fn default() -> Self {
        Self {
            system_id: "".to_string(),
            color: "".to_string(),
            scale: 1.0
        }
    }
}

impl AssetType for FluidFX {
    type InitPacketType = UpdateFluidFX;

    fn name() -> &'static str {
        "FluidFX"
    }

    fn path() -> &'static str {
        "Item/Block/FluidFX"
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
        let mut fluid_fx = HashMap::new();

        for (i, (id, _)) in map.iter().enumerate() {
            fluid_fx.insert(i as i32, FluidFXPacket {
                shader: ShaderType::None,
                fog_mode: FluidFog::Color,
                fog_color: Default::default(),
                fog_distance: Default::default(),
                fog_depth_start: 0.0,
                fog_depth_falloff: 0.0,
                colors_filter: Default::default(),
                colors_saturation: 0.0,
                distortion_amplitude: 0.0,
                distortion_frequency: 0.0,
                movement_settings: Default::default(),
                id: Some(id.clone()),
                particle: None,
            });
        }

        UpdateFluidFX {
            update_type: UpdateType::Init,
            max_id: fluid_fx.len() as i32,
            fluid_fx
        }
    }
}