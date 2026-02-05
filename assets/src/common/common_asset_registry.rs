use std::sync::{Arc, LazyLock, OnceLock};
use ahash::{HashMap, HashMapExt};
use parking_lot::{Mutex, RwLock};
use protocol::packets::setup::Asset;
use crate::common::common_asset::FileCommonAsset;

pub static COMMON_ASSET_REGISTRY: LazyLock<CommonAssetRegistry> = LazyLock::new(|| CommonAssetRegistry::new());

pub struct CommonAssetRegistry {
    pub asset_by_name: RwLock<HashMap<String, Vec<Arc<FileCommonAsset>>>>,
    pub asset_by_hash: RwLock<HashMap<String, Vec<Arc<FileCommonAsset>>>>,
    cache: RwLock<OnceLock<Vec<Arc<Asset>>>>,
}

impl CommonAssetRegistry {
    pub fn new() -> Self {
        Self {
            asset_by_name: RwLock::new(HashMap::new()),
            asset_by_hash: RwLock::new(HashMap::new()),
            cache: RwLock::new(OnceLock::new())
        }
    }

    pub fn add_common_asset(&self, asset: FileCommonAsset) {
        let mut by_name = self.asset_by_name.write();
        let mut by_hash = self.asset_by_hash.write();

        let list = by_name.entry(asset.name.clone()).or_insert_with(Vec::new);
        let mut active_changed = false;

        // Remove existing asset from same pack (if any)
        if let Some(pos) = list.iter().position(|a| a.pack == asset.pack) {
            // If it was active → remove from hash
            if pos == list.len() - 1 {
                Self::remove_from_hash(&mut by_hash, &list[pos]);
                active_changed = true;
            }
            list.remove(pos);
        }

        // If previous active exists and wasn't already removed
        if !active_changed {
            if let Some(prev_active) = list.last() {
                Self::remove_from_hash(&mut by_hash, prev_active);
            }
        }

        // Add new asset as active
        let arc = Arc::new(asset);
        list.push(arc.clone());
        by_hash
            .entry(arc.hash.clone())
            .or_insert_with(Vec::new)
            .push(arc);

        self.invalidate();
    }

    pub fn get_assets(&self) -> Vec<Arc<Asset>> {
        self.cache
            .read()
            .get_or_init(|| self.collect_assets())
            .clone()
    }

    fn collect_assets(&self) -> Vec<Arc<Asset>> {
        let by_name = self.asset_by_name.read();

        by_name
            .values()
            .filter_map(|list| list.last())
            .map(|asset| Arc::new(asset.to_packet()))
            .collect()
    }

    pub fn invalidate(&self) {
        self.cache.write().take();
    }

    fn remove_from_hash(
        by_hash: &mut HashMap<String, Vec<Arc<FileCommonAsset>>>,
        asset: &FileCommonAsset,
    ) {
        if let Some(list) = by_hash.get_mut(&asset.hash) {
            list.retain(|a| !(a.pack == asset.pack && a.name == asset.name));
            if list.is_empty() {
                by_hash.remove(&asset.hash);
            }
        }
    }
}