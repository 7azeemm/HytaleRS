use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::packets::assets::recipes::{BenchRequirementPacket, BenchType, CraftingRecipePacket, MaterialQuantityPacket, UpdateRecipes};
use protocol::packets::assets::repulsion::{RepulsionConfigPacket, UpdateRepulsionConfigs};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

//FIXME: in wrong place

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct CraftingRecipes {
    pub id: String,
    pub parent: Option<String>,
    pub inputs: Vec<MaterialQuantity>,
    pub outputs: Vec<MaterialQuantity>,
    pub primary_output: MaterialQuantity,
    pub primary_output_quantity: i32,
    pub bench_requirement: Vec<BenchRequirement>,
    pub time_seconds: f32,
    pub knowledge_required: bool,
    pub required_memories_level: i32,
}

impl Default for CraftingRecipes {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            parent: None,
            inputs: vec![],
            outputs: vec![],
            primary_output: Default::default(),
            primary_output_quantity: 1,
            bench_requirement: vec![],
            time_seconds: 0.0,
            knowledge_required: false,
            required_memories_level: 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct MaterialQuantity {
    pub item_id: Option<String>,
    pub resource_type_id: Option<String>,
    pub tag: String,
    pub tag_index: i32,
    pub quantity: i32,
    //Metadata
}

impl Default for MaterialQuantity {
    fn default() -> Self {
        Self {
            item_id: None,
            resource_type_id: None,
            tag: "".to_string(),
            tag_index: i32::MIN,
            quantity: 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct BenchRequirement {
    pub bench_type: BenchType,
    pub id: String,
    pub categories: Vec<String>,
    pub required_tier_level: i32
}

impl Default for BenchRequirement {
    fn default() -> Self {
        Self {
            bench_type: BenchType::Crafting,
            id: "".to_string(),
            categories: vec![],
            required_tier_level: 0,
        }
    }
}

impl AssetType for CraftingRecipes {
    type InitPacketType = UpdateRecipes;

    fn name() -> &'static str {
        "Recipes"
    }

    fn path() -> &'static str {
        "Item/Recipes"
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
        let mut recipes = HashMap::new();

        for (id, asset) in map.iter() {
            let inputs = asset.data.inputs.iter()
                .map(|b| MaterialQuantityPacket {
                    item_tag: b.tag_index,
                    quantity: b.quantity,
                    item_id: b.item_id.clone(),
                    resource_type_id: b.resource_type_id.clone(),
                })
                .collect();

            // let bench_requirement: Vec<BenchRequirementPacket> = asset.data.bench_requirement.iter()
            //     .map(|b| BenchRequirementPacket {
            //         bench_type: b.bench_type,
            //         required_tier_level: b.required_tier_level,
            //         id: Some(b.id.clone()),
            //         categories: b.categories.clone(),
            //     })
            //     .collect();

            recipes.insert(id.clone(), CraftingRecipePacket {
                knowledge_required: asset.data.knowledge_required,
                time_seconds: asset.data.time_seconds,
                required_memories_level: asset.data.required_memories_level,
                id: Some(id.clone()),
                inputs,
                outputs: vec![],
                primary_output: Some(MaterialQuantityPacket {
                    item_tag: asset.data.primary_output.tag_index,
                    quantity: asset.data.primary_output.quantity,
                    item_id: asset.data.primary_output.item_id.clone(),
                    resource_type_id: None,
                }),
                // bench_requirement,
                bench_requirement: vec![]
            });
            break;
        }

        UpdateRecipes {
            update_type: UpdateType::Init,
            recipes,
            removed_recipes: vec![],
        }
    }
}