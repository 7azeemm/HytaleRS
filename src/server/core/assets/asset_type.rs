use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::server::core::assets::AssetResult;

pub trait AssetType: Serialize + for<'de> Deserialize<'de> + Send + Sync + Sized + Clone {
    fn asset_type() -> &'static str;
    fn store_path() -> &'static str;
    fn id(&self) -> String;
    fn set_id(&mut self, id: String);
    fn parent(&self) -> Option<String> { None }
    fn get_contained(&self) -> Option<Vec<Value>> { None }
    fn validate(&self) -> AssetResult<()> { Ok(()) }
    fn get_cross_store_refs(&self) -> Vec<CrossStoreRef> { vec![] }
}

/// Reference to an asset in a different store
#[derive(Debug, Clone)]
pub struct CrossStoreRef {
    pub store_name: &'static str,
    pub asset_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetState {
    /// Just deserialized, parent not yet resolved
    Unresolved,
    /// Parent resolved and merged
    Resolved,
    /// Parent chain has cycle
    CircularParent,
    /// Validation failed
    Invalid,
}

#[derive(Clone)]
pub struct AssetWithMeta<T: AssetType> {
    pub asset: T,
    pub state: AssetState,
    pub origin_pack: String,
    pub origin_file: String,
}

impl<T: AssetType> AssetWithMeta<T> {
    pub fn new(asset: T, origin_pack: &str, origin_file: &str) -> Self {
        Self {
            asset,
            state: AssetState::Unresolved,
            origin_pack: origin_pack.to_string(),
            origin_file: origin_file.to_string(),
        }
    }

    pub fn mark_resolved(&mut self) {
        self.state = AssetState::Resolved;
    }

    pub fn mark_invalid(&mut self) {
        self.state = AssetState::Invalid;
    }

    pub fn mark_circular(&mut self) {
        self.state = AssetState::CircularParent;
    }
}
