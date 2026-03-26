use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::objects::objects::Opacity;
use protocol::packets::assets::block_type::{BlockMaterial, BlockSupportsRequiredForType, BlockTypePacket, DrawType, RandomRotation, Rotation, ShadingMode, UpdateBlockTypes, VariantRotation};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockType {
    pub id: String,
    pub parent: Option<String>,
    pub unknown: bool,
    pub group: Option<String>,
    pub block_particle_set_id: Option<String>,
    pub block_breaking_decal_id: Option<String>,
}

impl AssetType for BlockType {
    type InitPacketType = UpdateBlockTypes;

    fn name() -> &'static str {
        "BlockTypes"
    }

    fn path() -> &'static str {
        "Item/Block/Blocks"
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
        let mut block_types = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            let d = &asset.data;
            block_types.insert(i as i32, BlockTypePacket {
                unknown: d.unknown,
                draw_type: DrawType::Empty,
                material: BlockMaterial::Empty,
                opacity: Opacity::Solid,
                hitbox: 0,
                interaction_hitbox: 0,
                model_scale: 0.0,
                looping: false,
                max_support_distance: 0,
                block_supports_required_for: BlockSupportsRequiredForType::Any,
                requires_alpha_blending: false,
                cube_shading_mode: ShadingMode::Standard,
                random_rotation: RandomRotation::None,
                variant_rotation: VariantRotation::None,
                rotation_yaw_placement_offset: Rotation::None,
                block_sound_set_index: 0,
                ambient_sound_event_index: 0,
                particle_color: Default::default(),
                light: Default::default(),
                tint: Default::default(),
                biome_tint: Default::default(),
                group: 0,
                movement_settings: Default::default(),
                flags: Default::default(),
                placement_settings: Default::default(),
                ignore_support_when_placed: false,
                transition_to_tag: 0,
                item: Some(id.to_owned()),
                name: Some(id.to_owned()),
                shader_effect: vec![],
                model: Some(id.to_owned()),
                model_texture: vec![],
                model_animation: None,
                support: Default::default(),
                supporting: Default::default(),
                cube_textures: vec![],
                cube_side_mask_texture: None,
                conditional_sounds: vec![],
                particles: vec![],
                block_particle_set_id: d.block_particle_set_id.clone(),
                block_breaking_decal_id: d.block_breaking_decal_id.clone(),
                transition_texture: None,
                transition_to_groups: vec![],
                interaction_hint: None,
                gathering: None,
                display: None,
                rail: None,
                interactions: Default::default(),
                states: Default::default(),
                tag_indexes: vec![1],
                bench: None,
                connected_block_rule_set: None,
            });
        }

        UpdateBlockTypes {
            update_type: UpdateType::Init,
            max_id: block_types.len() as i32,
            update_block_textures: false,
            update_model_textures: false,
            update_models: false,
            update_map_geometry: false,
            block_types,
        }
    }
}