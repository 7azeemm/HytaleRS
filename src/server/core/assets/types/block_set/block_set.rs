use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockSet {
    pub id: Option<String>,
    pub name: Option<String>,
    pub parent: Option<String>,
    pub include_all: bool,
    pub include_block_types: Vec<String>,
    pub exclude_block_types: Vec<String>,
    pub include_block_groups: Vec<String>,
    pub exclude_block_groups: Vec<String>,
    pub include_hitbox_types: Vec<String>,
    pub exclude_hitbox_types: Vec<String>,
    pub include_categories: Vec<Vec<String>>,
    pub exclude_categories: Vec<Vec<String>>
}