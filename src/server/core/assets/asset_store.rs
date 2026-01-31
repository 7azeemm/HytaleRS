use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;
use log::{info, warn};
use serde_json::Value;

use crate::server::core::assets::asset_type::{AssetState, AssetType, AssetWithMeta};

/// Base trait for type-erased store access
pub trait StoreBase: Send + Sync {
    fn name(&self) -> &'static str;
    fn type_name(&self) -> &'static str;
    fn count(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn clear(&self);

    fn try_add_from_json(&self, id: &str, json: Value, origin: &str) -> Result<(), String>;

    fn get_asset_any(&self, id: &str) -> Option<Arc<dyn Any + Send + Sync>>;

    /// Get parent of asset by ID
    fn get_parent(&self, id: &str) -> Option<String>;

    /// Get all assets with unresolved parents
    fn get_unresolved(&self) -> Vec<String>;

    /// Mark asset as resolved
    fn mark_resolved(&self, id: &str);

    /// Get all children of a parent
    fn get_children(&self, parent_id: &str) -> Option<Vec<String>>;

    /// Get all contained assets (nested in parent)
    fn get_contained_in(&self, parent_id: &str) -> Option<Vec<String>>;

    /// Get all assets (for iteration)
    fn get_all_ids(&self) -> Vec<String>;

    /// Validate all assets
    fn validate_all(&self) -> Vec<(String, String)>;  // (id, error_msg)

    /// Get load stats
    fn get_stats(&self) -> StoreStats;
}

#[derive(Debug, Clone, Default)]
pub struct StoreStats {
    pub loaded: usize,
    pub failed: usize,
    pub invalid: usize,
    pub orphans: usize,  // assets with missing parents
}

/// Concrete store implementation for a specific asset type
pub struct AssetStore<T: AssetType> {
    /// All assets with metadata
    assets: RwLock<HashMap<String, AssetWithMeta<T>>>,

    /// Parent-child relationships: parent_id -> Set<child_ids>
    children: RwLock<HashMap<String, HashSet<String>>>,

    /// Contained-in relationships: parent_id -> Set<contained_ids>
    contained_in: RwLock<HashMap<String, HashSet<String>>>,

    /// Which assets are orphans (parent not found)
    orphans: RwLock<HashSet<String>>,

    /// Stats
    stats: RwLock<StoreStats>,
}

impl<T: AssetType> AssetStore<T> {
    pub fn new() -> Self {
        Self {
            assets: RwLock::new(HashMap::new()),
            children: RwLock::new(HashMap::new()),
            contained_in: RwLock::new(HashMap::new()),
            orphans: RwLock::new(HashSet::new()),
            stats: RwLock::new(StoreStats::default()),
        }
    }

    // ===== INSERTION =====

    /// Try to add asset from JSON (Phase 2)
    pub fn try_add_from_json(&self, id: &str, json: Value, origin: &str) -> Result<String, String> {
        // Deserialize
        let mut asset: T = serde_json::from_value(json)
            .map_err(|e| format!("Deserialize error: {}", e))?;

        asset.set_id(id.to_string());

        let id = asset.id();

        // Check duplicate
        if self.assets.read().contains_key(&id) {
            return Err(format!("Duplicate ID: {}", id));
        }

        // Create with metadata
        let mut with_meta = AssetWithMeta::new(asset, origin, "");

        // Validate
        if let Err(e) = with_meta.asset.validate() {
            with_meta.mark_invalid();
            warn!("Asset {} validation failed: {}", id, e);
            self.stats.write().invalid += 1;
            return Err(e.to_string());
        }

        // Store
        self.assets.write().insert(id.clone(), with_meta);
        self.stats.write().loaded += 1;

        Ok(id)
    }

    /// Mark asset resolved (Phase 3)
    pub fn mark_resolved(&self, id: &str) {
        if let Some(asset) = self.assets.write().get_mut(id) {
            asset.mark_resolved();
        }
    }

    /// Add parent-child relationship
    pub fn add_child(&self, parent_id: String, child_id: String) {
        self.children
            .write()
            .entry(parent_id)
            .or_insert_with(HashSet::new)
            .insert(child_id);
    }

    /// Add contained relationship
    pub fn add_contained(&self, parent_id: String, contained_id: String) {
        self.contained_in
            .write()
            .entry(parent_id)
            .or_insert_with(HashSet::new)
            .insert(contained_id);
    }

    /// Mark as orphan
    pub fn mark_orphan(&self, id: String) {
        self.orphans.write().insert(id);
        self.stats.write().orphans += 1;
    }

    // ===== RETRIEVAL =====

    pub fn get(&self, id: &str) -> Option<Arc<T>> {
        self.assets.read().get(id).map(|m| Arc::new(m.asset.clone()))
    }

    pub fn get_with_meta(&self, id: &str) -> Option<AssetWithMeta<T>> {
        self.assets.read().get(id).cloned()
    }

    pub fn get_all(&self) -> Vec<(String, Arc<T>)> {
        self.assets
            .read()
            .iter()
            .map(|(id, meta)| (id.clone(), Arc::new(meta.asset.clone())))
            .collect()
    }

    pub fn get_all_ids(&self) -> Vec<String> {
        self.assets.read().keys().cloned().collect()
    }

    pub fn count(&self) -> usize {
        self.assets.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.assets.read().is_empty()
    }

    // ===== RELATIONSHIPS =====

    pub fn get_children(&self, parent_id: &str) -> Option<Vec<String>> {
        self.children
            .read()
            .get(parent_id)
            .map(|set| set.iter().cloned().collect())
    }

    pub fn get_contained_in(&self, parent_id: &str) -> Option<Vec<String>> {
        self.contained_in
            .read()
            .get(parent_id)
            .map(|set| set.iter().cloned().collect())
    }

    pub fn get_parent(&self, id: &str) -> Option<String> {
        self.assets
            .read()
            .get(id)
            .and_then(|meta| meta.asset.parent())
    }

    /// Get unresolved assets (have parent but not marked resolved)
    pub fn get_unresolved(&self) -> Vec<String> {
        self.assets
            .read()
            .iter()
            .filter(|(_, meta)| meta.state == AssetState::Unresolved && meta.asset.parent().is_some())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Check for circular parent references
    pub fn check_circular_parents(&self) -> Vec<(String, String)> {
        let mut errors = Vec::new();
        let assets = self.assets.read();

        for (id, meta) in assets.iter() {
            if let Some(parent_id) = meta.asset.parent() {
                let mut visited = HashSet::new();
                if self.has_circular_chain(id, &parent_id, &mut visited, &assets) {
                    errors.push((id.clone(), parent_id));
                }
            }
        }

        errors
    }

    fn has_circular_chain(
        &self,
        original_id: &str,
        current_id: &str,
        visited: &mut HashSet<String>,
        assets: &HashMap<String, AssetWithMeta<T>>,
    ) -> bool {
        if current_id == original_id && !visited.is_empty() {
            return true;  // Found cycle
        }

        if !visited.insert(current_id.to_string()) {
            return false;  // Already visited, not the original cycle
        }

        if let Some(meta) = assets.get(current_id) {
            if let Some(parent_id) = meta.asset.parent() {
                return self.has_circular_chain(original_id, &parent_id, visited, assets);
            }
        }

        false
    }

    // ===== VALIDATION =====

    pub fn validate_all(&self) -> Vec<(String, String)> {
        let assets = self.assets.read();
        let mut errors = Vec::new();

        for (id, meta) in assets.iter() {
            if meta.state == AssetState::Invalid {
                errors.push((id.clone(), "Invalid state".into()));
            }

            if let Err(e) = meta.asset.validate() {
                errors.push((id.clone(), e.to_string()));
            }

            // Check parent exists
            if let Some(parent_id) = meta.asset.parent() {
                if !assets.contains_key(&parent_id) {
                    errors.push((id.clone(), format!("Parent not found: {}", parent_id)));
                }
            }
        }

        errors
    }

    // ===== STATE MANAGEMENT =====

    pub fn clear(&self) {
        self.assets.write().clear();
        self.children.write().clear();
        self.contained_in.write().clear();
        self.orphans.write().clear();
        self.stats.write().loaded = 0;
        self.stats.write().failed = 0;
        self.stats.write().invalid = 0;
        self.stats.write().orphans = 0;
    }

    pub fn get_stats(&self) -> StoreStats {
        self.stats.read().clone()
    }
}

impl<T: AssetType + 'static> StoreBase for AssetStore<T> {
    fn name(&self) -> &'static str {
        T::asset_type()
    }

    fn type_name(&self) -> &'static str {
        std::any::type_name::<T>()
    }

    fn count(&self) -> usize {
        AssetStore::count(self)
    }

    fn is_empty(&self) -> bool {
        AssetStore::is_empty(self)
    }

    fn clear(&self) {
        AssetStore::clear(self);
    }

    fn try_add_from_json(&self, id: &str, json: Value, origin: &str) -> Result<(), String> {
        AssetStore::try_add_from_json(self, id, json, origin)?;
        Ok(())
    }

    fn get_asset_any(&self, id: &str) -> Option<Arc<dyn Any + Send + Sync>> {
        AssetStore::get(self, id).map(|a| Arc::new(a) as Arc<dyn Any + Send + Sync>)
    }

    fn get_parent(&self, id: &str) -> Option<String> {
        AssetStore::get_parent(self, id)
    }

    fn get_unresolved(&self) -> Vec<String> {
        AssetStore::get_unresolved(self)
    }

    fn mark_resolved(&self, id: &str) {
        AssetStore::mark_resolved(self, id);
    }

    fn get_children(&self, parent_id: &str) -> Option<Vec<String>> {
        AssetStore::get_children(self, parent_id)
    }

    fn get_contained_in(&self, parent_id: &str) -> Option<Vec<String>> {
        AssetStore::get_contained_in(self, parent_id)
    }

    fn get_all_ids(&self) -> Vec<String> {
        AssetStore::get_all_ids(self)
    }

    fn validate_all(&self) -> Vec<(String, String)> {
        AssetStore::validate_all(self)
    }

    fn get_stats(&self) -> StoreStats {
        AssetStore::get_stats(self)
    }
}
