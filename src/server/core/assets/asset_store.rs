use std::any::{type_name, Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use async_trait::async_trait;
use log::{info, warn};
use parking_lot::RwLock;
use serde_json::Value;
use crate::server::core::assets::asset_reader::ZipReader;
use crate::server::core::assets::asset_type::{Asset, AssetType};
use crate::server::core::assets::structs::{RawAsset, StoreStats};

#[async_trait]
pub trait StoreBase: Any + Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn dependencies(&self) -> &'static [TypeId];
    async fn load_assets(self: Arc<Self>, reader: &Arc<ZipReader>);
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

pub struct AssetStore<T: AssetType> {
    assets: RwLock<HashMap<String, Asset<T>>>,

    children: RwLock<HashMap<String, HashSet<String>>>, // parent_id -> Set<child_ids>
    contained_in: RwLock<HashMap<String, HashSet<String>>>, // parent_id -> Set<contained_ids>
    orphans: RwLock<HashSet<String>>, // Which assets are orphans (parent not found)

    stats: RwLock<StoreStats>,
}

impl<T: AssetType + 'static> AssetStore<T> {
    pub fn new() -> Self {
        Self {
            assets: RwLock::new(HashMap::new()),
            children: RwLock::new(HashMap::new()),
            contained_in: RwLock::new(HashMap::new()),
            orphans: RwLock::new(HashSet::new()),
            stats: RwLock::new(StoreStats::default()),
        }
    }

    async fn decode_assets(self: Arc<Self>, raw_assets: Vec<RawAsset>, reader: &Arc<ZipReader>) {
        let len = raw_assets.len();
        info!("Decoding {} assets of store {}", len, self.name());
        let start = Instant::now();

        let mut handles = Vec::with_capacity(len);

        for raw in raw_assets {
            let self_clone = self.clone();
            let reader_clone = reader.clone();

            let handle = tokio::spawn(async move {
                self_clone.decode_asset(raw, reader_clone).await
            });
            handles.push(handle);
        }

        // Wait for all
        let results = futures::future::join_all(handles).await;

        info!("Decoded {} assets of store {} in {:.2?}", len, self.name(), start.elapsed());
    }

    async fn decode_asset(&self, raw_asset: RawAsset, reader: Arc<ZipReader>) {
        let start_time = Instant::now();

        let bytes = match reader.read_file(&raw_asset.path) {
            Ok(content) => content,
            Err(err) => {
                self.stats.write().invalid += 1;
                warn!("Failed to read asset file {}: {}", raw_asset.path, err);
                return;
            }
        };

        let mut asset: T = match serde_json::from_slice(&bytes) {
            Ok(asset) => asset,
            Err(err) => {
                self.stats.write().invalid += 1;
                warn!("Failed to decode asset {}: {}", raw_asset.path, err);
                return;
            }
        };

        info!("Decoded asset {} in {:.2?}", raw_asset.key, start_time.elapsed());

        asset.set_id(raw_asset.key.clone());
    }
}

#[async_trait]
impl<T: AssetType + 'static> StoreBase for AssetStore<T> {
    fn name(&self) -> &'static str {
        T::name()
    }

    fn dependencies(&self) -> &'static [TypeId] {
        T::dependencies()
    }

    async fn load_assets(self: Arc<Self>, reader: &Arc<ZipReader>) {
        let store_path = format!("Server/{}", T::path());
        let paths: Vec<&String> = reader.iter(&store_path, T::extension()).collect();

        let mut raw_assets = Vec::with_capacity(paths.len());
        for path in paths {
            match path.split('/').last().and_then(|s| s.strip_suffix(T::extension())) {
                Some(key) => {
                    raw_assets.push(RawAsset {
                        key: key.to_owned(),
                        path: path.to_owned(),
                    });
                },
                None => {
                    self.stats.write().invalid += 1;
                    warn!("Invalid asset path: {}", path);
                }
            }
        }

        self.decode_assets(raw_assets, &reader).await;
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}
