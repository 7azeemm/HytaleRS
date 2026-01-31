use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use log::{info, warn};
use parking_lot::RwLock;
use crate::server::core::assets::asset_type::AssetType;
use crate::server::core::assets::{AssetError, AssetResult};
use crate::server::core::assets::asset_store::{AssetStore, StoreBase};

pub static STORE_REGISTRY: LazyLock<StoreRegistry> = LazyLock::new(|| StoreRegistry::new());

/// Type information for an asset type
#[derive(Clone)]
pub struct AssetTypeInfo {
    pub name: &'static str,
    pub store_path: &'static str,
    pub type_id: TypeId,
}

pub struct StoreRegistry {
    /// Stores indexed by asset type name: "BlockSet", "Item", etc.
    stores: RwLock<HashMap<&'static str, Arc<dyn StoreBase>>>,

    /// Type info indexed by type name
    info: RwLock<HashMap<&'static str, AssetTypeInfo>>,

    /// Type name to type id mapping
    type_ids: RwLock<HashMap<TypeId, &'static str>>,
}

impl StoreRegistry {
    pub fn new() -> Self {
        Self {
            stores: RwLock::new(HashMap::new()),
            info: RwLock::new(HashMap::new()),
            type_ids: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new asset type
    pub fn register<T: AssetType + 'static>(&self) {
        let store = Arc::new(AssetStore::<T>::new());
        let type_name = T::asset_type();
        let type_id = TypeId::of::<T>();

        self.stores.write().insert(type_name, store);
        self.info.write().insert(
            type_name,
            AssetTypeInfo {
                name: type_name,
                store_path: T::store_path(),
                type_id,
            },
        );
        self.type_ids.write().insert(type_id, type_name);

        info!("Registered asset type: {} (path: {})", type_name, T::store_path());
    }

    // ===== STORE ACCESS =====

    /// Get store by type name (for type-erased access)
    pub fn get_store(&self, type_name: &str) -> Option<Arc<dyn StoreBase>> {
        self.stores.read().get(type_name).cloned()
    }

    /// Get store with type checking
    pub fn get_store_typed<T: AssetType + 'static>(&self) -> AssetResult<Arc<AssetStore<T>>> {
        self.stores.read()
            .get(T::asset_type())
            .ok_or_else(|| AssetError::TypeNotRegistered(T::asset_type().to_string()))
            .and_then(|store| {
                // Try to cast
                Err(AssetError::TypeError("Store exists but type mismatch".into()))
            })
    }

    /// Get all stores
    pub fn get_all_stores(&self) -> Vec<Arc<dyn StoreBase>> {
        self.stores.read().values().cloned().collect()
    }

    /// Get all type info
    pub fn get_all_types(&self) -> Vec<AssetTypeInfo> {
        self.info.read().values().cloned().collect()
    }

    // ===== TYPE INFO =====

    /// Get type info
    pub fn get_type_info(&self, type_name: &str) -> Option<AssetTypeInfo> {
        self.info.read().get(type_name).cloned()
    }

    /// Get type name by store path
    pub fn get_type_by_path(&self, path: &str) -> Option<&'static str> {
        self.info.read()
            .values()
            .find(|info| path.contains(info.store_path))
            .map(|info| info.name)
    }

    /// Get store path for type
    pub fn get_store_path(&self, type_name: &str) -> Option<&'static str> {
        self.info.read().get(type_name).map(|i| i.store_path)
    }

    // ===== STATISTICS =====

    /// Get total asset count across all stores
    pub fn total_count(&self) -> usize {
        self.stores.read().values().map(|s| s.count()).sum()
    }

    /// Get count per store
    pub fn counts_by_store(&self) -> HashMap<&'static str, usize> {
        self.stores.read()
            .iter()
            .map(|(name, store)| (*name, store.count()))
            .collect()
    }

    /// Get stats for all stores
    pub fn get_all_stats(&self) -> HashMap<&'static str, String> {
        self.stores.read()
            .iter()
            .map(|(name, store)| {
                let stats = store.get_stats();
                let stat_str = format!(
                    "loaded={} failed={} invalid={} orphans={}",
                    stats.loaded, stats.failed, stats.invalid, stats.orphans
                );
                (*name, stat_str)
            })
            .collect()
    }

    // ===== VALIDATION =====

    /// Validate all assets in all stores
    pub fn validate_all(&self) -> HashMap<&'static str, Vec<(String, String)>> {
        self.stores.read()
            .iter()
            .map(|(name, store)| (*name, store.validate_all()))
            .filter(|(_, errors)| !errors.is_empty())
            .collect()
    }

    /// Check for circular references across stores
    pub fn check_circular_references(&self) -> Vec<(String, String, String)> {
        // type_name, asset_id, description
        let mut errors = Vec::new();

        for store in self.stores.read().values() {
            // Note: Need to implement this per-store type
            // For now just track that we'd validate
        }

        errors
    }

    // ===== DIAGNOSTICS =====

    pub fn print_summary(&self) {
        info!("=== Asset Registry Summary ===");
        info!("Total stores registered: {}", self.stores.read().len());
        info!("Total assets loaded: {}", self.total_count());

        for (name, count) in self.counts_by_store() {
            info!("  {}: {} assets", name, count);
        }

        let errors = self.validate_all();
        if !errors.is_empty() {
            warn!("=== Validation Errors ===");
            for (store_name, store_errors) in errors {
                warn!("  {}: {} errors", store_name, store_errors.len());
                for (id, error) in store_errors.iter().take(5) {
                    warn!("    {}: {}", id, error);
                }
                if store_errors.len() > 5 {
                    warn!("    ... and {} more", store_errors.len() - 5);
                }
            }
        }
    }
}
