use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, ColorLight, Direction, FloatRange, Vec2f, Vec3f};
use crate::packets::assets::builder_tools::ItemBuilderToolData;
use crate::packets::assets::entity_effect::ValueType;
use crate::packets::assets::interaction_type::InteractionType;
use crate::packets::assets::item_animations::ItemPullbackConfigPacket;
use crate::packets::assets::model_particle::{EntityPart, ModelParticlePacket};
use crate::packets::assets::root_interactions::GameMode;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 54, max_size = 0x64000000, compressed)]
pub struct UpdateItems {
    pub update_type: UpdateType,
    pub update_models: bool,
    pub update_icons: bool,
    pub items: HashMap<String, ItemBasePacket>,
    pub removed_items: Vec<String>
}

#[packet_field]
pub struct ItemBasePacket {
    pub scale: f32,
    pub use_player_animations: bool,
    pub max_stack: i32,
    pub reticle_index: i32,
    pub icon_properties: FixedOption<AssetIconProperties>,
    pub item_level: i32,
    pub quality_index: i32,
    pub consumable: bool,
    pub variant: bool,
    pub block_id: i32,
    pub glider_config: FixedOption<ItemGlider>,
    pub block_selector_tool: FixedOption<BlockSelectorToolData>,
    pub light: FixedOption<ColorLight>,
    pub durability: f64,
    pub sound_event_index: i32,
    pub item_sound_set_index: i32,
    pub pullback_config: FixedOption<ItemPullbackConfigPacket>,
    pub clips_geometry: bool,
    pub render_deployable_preview: bool,
    pub id: Option<String>,
    pub model: Option<String>,
    pub texture: Option<String>,
    pub animation: Option<String>,
    pub player_animations_id: Option<String>,
    pub icon: Option<String>,
    pub translation_properties: Option<ItemTranslationProperties>,
    pub resource_types: Vec<ItemResourceType>,
    pub tool: Option<ItemTool>,
    pub weapon: Option<ItemWeapon>,
    pub armor: Option<ItemArmor>,
    pub utility: Option<ItemUtility>,
    pub builder_tool_data: Option<ItemBuilderToolData>,
    pub item_entity: Option<ItemEntityConfig>,
    pub set: Option<String>,
    pub categories: Vec<String>,
    pub particles: Vec<ModelParticlePacket>,
    pub first_person_particles: Vec<ModelParticlePacket>,
    pub trails: Vec<ModelTrail>,
    pub interactions: HashMap<InteractionType, i32>,
    pub interaction_vars: HashMap<String, i32>,
    pub interaction_config: Option<InteractionConfiguration>,
    pub dropped_item_animation: Option<String>,
    pub tag_indexes: Vec<i32>,
    pub item_appearance_conditions: HashMap<String, Vec<ItemAppearanceCondition>>,
    pub display_entity_stats_hud: Vec<i32>,
}

#[packet_field]
pub struct AssetIconProperties {
    pub scale: f32,
    pub translation: FixedOption<Vec2f>,
    pub rotation: FixedOption<Vec3f>
}

#[packet_field]
pub struct ItemTranslationProperties {
    pub name: Option<String>,
    pub description: Option<String>
}

#[packet_field]
pub struct ItemGlider {
    pub terminal_velocity: f32,
    pub fall_speed_multiplier: f32,
    pub horizontal_speed_multiplier: f32,
    pub speed: f32
}

#[packet_field]
pub struct BlockSelectorToolData {
    pub durability_loss_on_use: f32
}

#[packet_field]
pub struct ItemResourceType {
    pub quantity: i32,
    pub id: Option<String>
}

#[packet_field]
pub struct ItemTool {
    pub speed: f32,
    pub specs: Vec<ItemToolSpec>
}

#[packet_field]
pub struct ItemToolSpec {
    pub power: f32,
    pub quality: i32,
    pub gather_type: Option<String>
}

#[packet_field]
pub struct ItemWeapon {
    pub render_dual_wielded: bool,
    pub entity_stats_to_clear: Vec<i32>,
    pub stat_modifiers: HashMap<i32, Vec<Modifier>>
}

#[packet_field]
pub struct Modifier {
    pub target: ModifierTarget,
    pub calculation_type: CalculationType,
    pub amount: f32,
}

#[packet_enum]
pub enum ModifierTarget {
    Min,
    Max
}

#[packet_enum]
pub enum CalculationType {
    Additive,
    Multiplicative
}

#[packet_field]
pub struct ItemArmor {
    pub armor_slot: ItemArmorSlot,
    pub base_damager_resistance: f64,
    pub cosmetics_to_hide: Vec<Cosmetic>,
    pub stat_modifiers: HashMap<i32, Vec<Modifier>>,
    pub damage_resistance: HashMap<i32, Vec<Modifier>>,
    pub damage_enhancement: HashMap<i32, Vec<Modifier>>,
    pub damage_class_enhancement: HashMap<i32, Vec<Modifier>>,
}

#[packet_enum]
pub enum ItemArmorSlot {
    Head,
    Chest,
    Hands,
    Legs
}

#[packet_enum]
pub enum Cosmetic {
    Haircut,
    FacialHair,
    Undertop,
    Overtop,
    Pants,
    Overpants,
    Shoes,
    Gloves,
    Cape,
    HeadAccessory,
    FaceAccessory,
    EarAccessory,
    Ear
}

#[packet_field]
pub struct ItemUtility {
    pub usable: bool,
    pub compatible: bool,
    pub entity_stats_to_clear: Vec<i32>,
    pub stat_modifiers: HashMap<i32, Vec<Modifier>>
}

#[packet_field]
pub struct ItemEntityConfig {
    pub particle_color: FixedOption<Color>,
    pub show_item_particles: bool,
    pub particle_system_id: Option<String>,
}

#[packet_field]
pub struct ModelTrail {
    pub target_entity_part: EntityPart,
    pub position_offset: FixedOption<Vec3f>,
    pub rotation_offset: FixedOption<Direction>,
    pub fixed_rotation: bool,
    pub trail_id: Option<String>,
    pub target_node_name: Option<String>,
}

#[packet_field]
pub struct InteractionConfiguration {
    pub display_outlines: bool,
    pub debug_outlines: bool,
    pub all_entities: bool,
    pub use_distance: HashMap<GameMode, f32>,
    pub priorities: HashMap<InteractionType, InteractionPriority>,
}

#[packet_field]
pub struct InteractionPriority {
    pub values: HashMap<PrioritySlot, i32>
}

#[packet_enum]
#[derive(Eq, PartialEq, Hash)]
pub enum PrioritySlot {
    Default,
    MainHand,
    OffHand
}

#[packet_field]
pub struct ItemAppearanceCondition {
    pub condition: FixedOption<FloatRange>,
    pub condition_value_type: ValueType,
    pub local_sound_event_id: i32,
    pub world_sound_event_id: i32,
    pub particles: Vec<ModelParticlePacket>,
    pub first_person_particles: Vec<ModelParticlePacket>,
    pub model: Option<String>,
    pub texture: Option<String>,
    pub model_vfx_id: Option<String>
}