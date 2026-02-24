use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, ColorLight, Opacity};
use crate::packets::assets::block_textures::BlockTexturesPacket;
use crate::packets::assets::model_particle::ModelParticlePacket;
use crate::packets::assets::shader_type::ShaderType;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 83, max_size = 0x64000000, compressed)]
pub struct UpdateFluids {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub fluids: HashMap<i32, FluidPacket>,
}

#[packet_field]
pub struct FluidPacket {
    pub max_fluid_level: i32,
    pub required_alpha_blending: bool,
    pub opacity: Opacity,
    pub light: FixedOption<ColorLight>,
    pub draw_type: FluidDrawType,
    pub fluid_fx_index: i32,
    pub block_sound_set_index: i32,
    pub particle_color: FixedOption<Color>,
    pub id: Option<String>,
    pub cube_textures: Vec<BlockTexturesPacket>,
    pub shader_effect: Vec<ShaderType>,
    pub particles: Vec<ModelParticlePacket>,
    pub block_particle_set_id: Option<String>,
    pub tag_indexes: Vec<i32>
}

#[packet_enum]
pub enum FluidDrawType {
    None,
    Liquid
}