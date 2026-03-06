use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::FixedOption;
use protocol::objects::objects::{Color, ColorLight, Opacity};
use protocol::packets::assets::fluid::{FluidDrawType, FluidPacket, UpdateFluids};
use protocol::packets::assets::interactions::interaction_type::InteractionType;
use crate::assets::types::block_textures::BlockTextures;
use protocol::packets::assets::shader_type::ShaderType;
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};
use crate::assets::types::model_particle::ModelParticle;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Fluid {
    pub id: String,
    pub parent: Option<String>,
    pub max_fluid_level: i32,
    pub textures: Vec<BlockTextures>,
    pub effect: Vec<ShaderType>,
    pub particles: Vec<ModelParticle>,
    pub draw_type: FluidDrawType,
    pub opacity: Opacity,
    pub requires_alpha_blending: bool,
    #[serde(rename = "FluidFXId")]
    pub fluid_fx_id: String,
    // pub ticker: HashMap<String, bool>,
    pub damage_to_entities: i32,
    // pub light: Option<String>,//FIXME: ColorLight
    // pub particle_color: Option<String>,//FIXME: Color
    pub block_sound_set_id: String,
    // pub block_particle_set_id: Option<String>,
    // pub interactions: HashMap<InteractionType, String>,
}

//FIXME: CodecMap
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct FluidTicker {
    pub system_id: String,
    pub color: Option<String>,//FIXME: Color
    pub scale: f32, // Def: 1.0
}

impl Default for Fluid {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            parent: None,
            max_fluid_level: 8,
            textures: vec![],
            effect: vec![],
            particles: vec![],
            draw_type: FluidDrawType::Liquid,
            opacity: Opacity::Solid,
            requires_alpha_blending: true,
            fluid_fx_id: "Empty".to_string(),
            // ticker: Default::default(),//DefaultTicker
            damage_to_entities: 0,
            // light: Default::default(),
            // particle_color: Default::default(),
            block_sound_set_id: "Empty".to_string(),
            // block_particle_set_id: None,
            // interactions: Default::default(),
        }
    }
}

impl AssetType for Fluid {
    type InitPacketType = UpdateFluids;

    fn name() -> &'static str {
        "Fluids"
    }

    fn path() -> &'static str {
        "Item/Block/Fluids"
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
        let mut fluids = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            fluids.insert(i as i32, FluidPacket {
                max_fluid_level: 8,
                required_alpha_blending: true,
                opacity: Opacity::Solid,
                light: FixedOption(ColorLight::default().into()),
                draw_type: FluidDrawType::Liquid,
                fluid_fx_index: 0,
                block_sound_set_index: 0,
                particle_color: FixedOption(Color::default().into()),
                id: Some(id.to_owned()),
                cube_textures: vec![BlockTextures::default().to_packet(1.0)],
                shader_effect: vec![ShaderType::None],
                particles: vec![],
                block_particle_set_id: Some(asset.data.block_sound_set_id.clone()),
                tag_indexes: vec![0],
            });
            break;
        }

        UpdateFluids {
            update_type: UpdateType::Init,
            max_id: fluids.len() as i32,
            fluids
        }
    }
}