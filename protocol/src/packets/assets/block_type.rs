use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, ColorLight, Opacity, Vec3f, Vec3i};
use crate::packets::assets::block_textures::BlockTexturesPacket;
use crate::packets::assets::interactions::interaction_type::InteractionType;
use crate::packets::assets::model_particle::ModelParticlePacket;
use crate::packets::assets::recipes::MaterialQuantityPacket;
use crate::packets::assets::shader_type::ShaderType;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 40, max_size = 0x64000000, compressed)]
pub struct UpdateBlockTypes {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub update_block_textures: bool,
    pub update_model_textures: bool,
    pub update_models: bool,
    pub update_map_geometry: bool,
    pub block_types: HashMap<i32, BlockTypePacket>,
}

#[packet_field]
pub struct BlockTypePacket {
    pub unknown: bool,
    pub draw_type: DrawType,
    pub material: BlockMaterial,
    pub opacity: Opacity,
    pub hitbox: i32,
    pub interaction_hitbox: i32,
    pub model_scale: f32,
    pub looping: bool,
    pub max_support_distance: i32,
    pub block_supports_required_for: BlockSupportsRequiredForType,
    pub requires_alpha_blending: bool,
    pub cube_shading_mode: ShadingMode,
    pub random_rotation: RandomRotation,
    pub variant_rotation: VariantRotation,
    pub rotation_yaw_placement_offset: Rotation,
    pub block_sound_set_index: i32,
    pub ambient_sound_event_index: i32,
    pub particle_color: FixedOption<Color>,
    pub light: FixedOption<ColorLight>,
    pub tint: FixedOption<Tint>,
    pub biome_tint: FixedOption<Tint>,
    pub group: i32,
    pub movement_settings: FixedOption<BlockMovementSettings>,
    pub flags: FixedOption<BlockFlags>,
    pub placement_settings: FixedOption<BlockPlacementSettings>,
    pub ignore_support_when_placed: bool,
    pub transition_to_tag: i32,
    pub item: Option<String>,
    pub name: Option<String>,
    pub shader_effect: Vec<ShaderType>,
    pub model: Option<String>,
    pub model_texture: Vec<ModelTexture>,
    pub model_animation: Option<String>,
    pub support: HashMap<BlockNeighbor, Vec<RequiredBlockFaceSupport>>,
    pub supporting: HashMap<BlockNeighbor, Vec<BlockFaceSupport>>,
    pub cube_textures: Vec<BlockTexturesPacket>,
    pub cube_side_mask_texture: Option<String>,
    pub conditional_sounds: Vec<ConditionalBlockSound>,
    pub particles: Vec<ModelParticlePacket>,
    pub block_particle_set_id: Option<String>,
    pub block_breaking_decal_id: Option<String>,
    pub transition_texture: Option<String>,
    pub transition_to_groups: Vec<i32>,
    pub interaction_hint: Option<String>,
    pub gathering: Option<BlockGathering>,
    pub display: Option<ModelDisplay>,
    pub rail: Option<RailConfig>,
    pub interactions: HashMap<InteractionType, i32>,
    pub states: HashMap<String, i32>,
    pub tag_indexes: Vec<i32>,
    pub bench: Option<Bench>,
    pub connected_block_rule_set: Option<ConnectedBlockRuleSet>
}

#[packet_field]
pub struct RequiredBlockFaceSupport {
    pub block_type_id: i32,
    pub tag_index: i32,
    pub fluid_id: i32,
    pub support: SupportMatch,
    pub match_self: SupportMatch,
    pub allow_support_propagation: bool,
    pub rotate: bool,
    pub face_type: Option<String>,
    pub self_face_type: Option<String>,
    pub block_set_id: Option<String>,
    pub filter: Vec<Vec3i>,
}

#[packet_field]
pub struct BlockFaceSupport {
    pub face_type: Option<String>,
    pub filter: Vec<Vec3i>
}

#[packet_field]
pub struct BlockPlacementSettings {
    pub allow_rotation_key: bool,
    pub place_in_empty_blocks: bool,
    pub preview_visibility: BlockPreviewVisibility,
    pub rotation_mode: BlockPlacementRotationMode,
    pub wall_placement_override_block_id: i32,
    pub floor_placement_override_block_id: i32,
    pub ceiling_placement_override_block_id: i32,
    pub allow_break_replace: bool,
}

#[packet_field]
pub struct ModelDisplay {
    pub translation: FixedOption<Vec3f>,
    pub rotation: FixedOption<Vec3f>,
    pub scale: FixedOption<Vec3f>,
    pub node: Option<String>,
    pub attach_to: Option<String>,
}

#[packet_field]
pub struct RailConfig {
    pub points: Vec<RailPoint>
}

#[packet_field]
pub struct RailPoint {
    pub point: FixedOption<Vec3f>,
    pub normal: FixedOption<Vec3f>,
}

#[packet_field]
pub struct Bench {
    pub bench_tier_levels: Vec<BenchTierLevel>
}

#[packet_field]
pub struct BenchTierLevel {
    pub crafting_time_reduction_modifier: f64,
    pub extra_input_slot: i32,
    pub extra_output_slot: i32,
    pub bench_upgrade_requirement: Option<BenchUpgradeRequirement>
}

#[packet_field]
pub struct BenchUpgradeRequirement {
    pub time_seconds: f64,
    pub material: Vec<MaterialQuantityPacket>
}

#[packet_field]
pub struct ConnectedBlockRuleSet {
    pub connected_block_rule_set_type: ConnectedBlockRuleSetType,
    pub stair: Option<StairConnectedBlockRuleSet>,
    pub roof: Option<RoofConnectedBlockRuleSet>
}

#[packet_field]
pub struct StairConnectedBlockRuleSet {
    pub straight_block_id: i32,
    pub corner_left_block_id: i32,
    pub corner_right_block_id: i32,
    pub inverted_corner_left_block_id: i32,
    pub inverted_corner_right_block_id: i32,
    pub material_name: Option<String>,
}

#[packet_field]
pub struct RoofConnectedBlockRuleSet {
    pub topper_block_id: i32,
    pub width: i32,
    pub regular: Option<StairConnectedBlockRuleSet>,
    pub hollow: Option<StairConnectedBlockRuleSet>,
    pub material_name: Option<String>
}

#[packet_field]
pub struct Tint {
    pub top: i32,
    pub bottom: i32,
    pub front: i32,
    pub back: i32,
    pub left: i32,
    pub right: i32
}

#[packet_field]
pub struct BlockMovementSettings {
    pub is_climbable: bool,
    pub climb_up_speed_multiplier: f32,
    pub climb_down_speed_multiplier: f32,
    pub climb_literal_speed_multiplier: f32,
    pub is_bouncy: bool,
    pub bounce_velocity: f32,
    pub drag: f32,
    pub friction: f32,
    pub terminal_velocity_modifier: f32,
    pub horizontal_speed_multiplier: f32,
    pub acceleration: f32,
    pub jump_force_multiplier: f32
}

#[packet_field]
pub struct BlockFlags {
    pub is_usable: bool,
    pub is_stackable: bool
}

#[packet_field]
pub struct BlockGathering {
    pub breaking: Option<BlockBreaking>,
    pub harvest: Option<Harvesting>,
    pub soft: Option<SoftBlock>
}

#[packet_field]
pub struct BlockBreaking {
    pub health: f32,
    pub quantity: i32,
    pub quality: i32,
    pub gather_type: Option<String>,
    pub item_id: Option<String>,
    pub drop_list_id: Option<String>
}

#[packet_field]
pub struct Harvesting {
    pub item_id: Option<String>,
    pub drop_list_id: Option<String>
}

#[packet_field]
pub struct SoftBlock {
    pub is_weapon_breakable: bool,
    pub item_id: Option<String>,
    pub drop_list_id: Option<String>,
}

#[packet_field]
pub struct ModelTexture {
    pub weight: f32,
    pub texture: Option<String>
}

#[packet_field]
pub struct ConditionalBlockSound {
    pub sound_event_index: i32,
    pub ambience_fx_index: i32
}

#[packet_enum]
pub enum ConnectedBlockRuleSetType {
    Stair,
    Roof
}

#[packet_enum]
pub enum BlockPreviewVisibility {
    AlwaysVisible,
    AlwaysHidden,
    Default
}

#[packet_enum]
pub enum BlockPlacementRotationMode {
    FacingPlayer,
    StairFacingPlayer,
    BlockNormal,
    Default
}

#[packet_enum]
pub enum SupportMatch {
    Ignored,
    Required,
    Disallowed
}

#[packet_enum]
pub enum DrawType {
    Empty,
    GizmoCube,
    Cube,
    Model,
    CubeWithModel
}

#[packet_enum]
pub enum VariantRotation {
    None,
    Wall,
    UpDown,
    Pipe,
    DoublePipe,
    NESW,
    UpDownNESW,
    All
}

#[packet_enum]
pub enum Rotation {
    None,
    Ninety,
    OneEighty,
    TwoSeventy,
}

#[packet_enum]
pub enum BlockMaterial {
    Empty,
    Solid
}

#[packet_enum]
pub enum ShadingMode {
    Standard,
    Flat,
    FullBright,
    Reflective
}

#[packet_enum]
pub enum RandomRotation {
    None,
    YawPitchRollStep1,
    YawStep1,
    YawStep1XZ,
    YawStep90
}

#[packet_enum]
pub enum BlockSupportsRequiredForType {
    Any,
    All
}

#[derive(Eq, PartialEq, Hash)]
#[packet_enum]
pub enum BlockNeighbor {
    Up,
    Down,
    North,
    East,
    South,
    West,
    UpNorth,
    UpSouth,
    UpEast,
    UpWest,
    DownNorth,
    DownSouth,
    DownEast,
    DownWest,
    NorthEast,
    SouthEast,
    SouthWest,
    NorthWest,
    UpNorthEast,
    UpSouthEast,
    UpSouthWest,
    UpNorthWest,
    DownNorthEast,
    DownSouthEast,
    DownSouthWest,
    DownNorthWest
}