use serde::{Deserialize, Serialize};
use crate::assets::asset_type::AssetType;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockSet {
    pub id: String,
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

impl AssetType for BlockSet {
    fn name() -> &'static str {
        "BlockSets"
    }

    fn path() -> &'static str {
        "Item/Block/Sets"
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
}