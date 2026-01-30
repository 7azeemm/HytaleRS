use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;

#[derive(Debug)]
pub struct AssetMap<T: Send + Sync + Debug + 'static> {
    assets: RwLock<HashMap<String, T>>,
    metadata: RwLock<HashMap<String, AssetMetadata>>,
    next_index: AtomicUsize,
}

#[derive(Clone, Debug)]
struct AssetMetadata {
    pack_origin: String,
    network_index: usize,
}

impl<T: Send + Sync + Debug + 'static> AssetMap<T> {
    pub fn new() -> Self {
        Self {
            assets: RwLock::new(HashMap::new()),
            metadata: RwLock::new(HashMap::new()),
            next_index: AtomicUsize::new(0),
        }
    }

    // #[inline]
    // pub fn get(&self, key: &str) -> Option<T> {
    //     self.assets.read().get(key).cloned()
    // }

    pub fn insert(&self, key: impl Into<String>, asset: T, pack_origin: &str) {
        let key_str = key.into();

        // Store asset
        self.assets.write().insert(key_str.clone(), asset);

        // Assign index on first insertion
        let mut metadata_map = self.metadata.write();
        if !metadata_map.contains_key(&key_str) {
            let index = self.next_index.fetch_add(1, Ordering::SeqCst);
            metadata_map.insert(
                key_str.clone(),
                AssetMetadata {
                    pack_origin: pack_origin.to_string(),
                    network_index: index,
                },
            );
        }
    }

    /// Remove asset
    pub fn remove(&self, key: &str) -> Option<T> {
        self.metadata.write().remove(key);
        self.assets.write().remove(key)
    }

    // ========== NETWORK INDEXING ==========

    /// Get network index for asset (for efficient network transmission)
    /// Used like: asset_index[0] = AssetType::MyAsset("id1")
    #[inline]
    pub fn get_index(&self, key: &str) -> Option<usize> {
        self.metadata.read().get(key).map(|m| m.network_index)
    }

    /// Get next index that will be assigned
    #[inline]
    pub fn next_index(&self) -> usize {
        self.next_index.load(Ordering::SeqCst)
    }

    // ========== PACK MANAGEMENT ==========

    /// Remove all assets from a specific pack
    pub fn remove_pack(&self, pack_name: &str) -> usize {
        let metadata = self.metadata.read();
        let keys_to_remove: Vec<String> = metadata
            .iter()
            .filter(|(_, m)| m.pack_origin == pack_name)
            .map(|(k, _)| k.clone())
            .collect();
        drop(metadata);

        let mut count = 0;
        for key in keys_to_remove {
            if self.remove(&key).is_some() {
                count += 1;
            }
        }
        count
    }

    /// Get all assets from a pack
    // pub fn get_by_pack(&self, pack_name: &str) -> Vec<(String, T)> {
    //     let metadata = self.metadata.read();
    //     let assets = self.assets.read();
    //
    //     metadata
    //         .iter()
    //         .filter(|(_, m)| m.pack_origin == pack_name)
    //         .filter_map(|(key, _)| {
    //             assets
    //                 .get(key)
    //                 .map(|asset| (key.clone(), asset.clone()))
    //         })
    //         .collect()
    // }

    /// Get origin pack of an asset
    #[inline]
    pub fn get_origin(&self, key: &str) -> Option<String> {
        self.metadata.read().get(key).map(|m| m.pack_origin.clone())
    }

    // ========== INTROSPECTION ==========

    /// Get all assets
    // pub fn get_all(&self) -> Vec<(String, T)> {
    //     let assets = self.assets.read();
    //     assets
    //         .iter()
    //         .map(|(k, v)| (k.clone(), v.clone()))
    //         .collect()
    // }

    /// Get asset count
    #[inline]
    pub fn len(&self) -> usize {
        self.assets.read().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.assets.read().is_empty()
    }

    /// Get all metadata (for debugging)
    pub fn get_metadata(&self) -> Vec<(String, String, usize)> {
        self.metadata
            .read()
            .iter()
            .map(|(k, m)| (k.clone(), m.pack_origin.clone(), m.network_index))
            .collect()
    }

    /// Clear all assets (dangerous, be careful!)
    pub fn clear(&self) {
        self.assets.write().clear();
        self.metadata.write().clear();
        // Note: next_index is NOT reset - indices are immutable once assigned
    }
}
