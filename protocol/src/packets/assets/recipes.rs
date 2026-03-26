use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 60, max_size = 0x64000000, compressed)]
pub struct UpdateRecipes {
    pub update_type: UpdateType,
    pub recipes: HashMap<String, CraftingRecipePacket>,
    pub removed_recipes: Vec<String>
}

#[packet_field]
pub struct CraftingRecipePacket {
    pub knowledge_required: bool,
    pub time_seconds: f32,
    pub required_memories_level: i32,
    pub id: Option<String>,
    pub inputs: Vec<MaterialQuantityPacket>,
    pub outputs: Vec<MaterialQuantityPacket>,
    pub primary_output: Option<MaterialQuantityPacket>,
    pub bench_requirement: Vec<BenchRequirementPacket>
}

#[packet_field]
pub struct MaterialQuantityPacket {
    pub item_tag: i32,
    pub quantity: i32,
    pub item_id: Option<String>,
    pub resource_type_id: Option<String>,
}

#[packet_field]
pub struct BenchRequirementPacket {
    pub bench_type: BenchType,
    pub required_tier_level: i32,
    pub id: String,
    pub categories: Vec<String>
}

#[packet_enum]
pub enum BenchType {
    Crafting,
    Processing,
    DiagramCrafting,
    StructuralCrafting
}