use std::any::{type_name, Any, TypeId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use async_trait::async_trait;
use futures::future::join_all;
use log::{info, warn};
use parking_lot::{Mutex, RwLock};
use rayon::iter::Either;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use serde_json::Value;
use crate::assets::asset_reader::ZipReader;
use crate::assets::asset_type::{Asset, AssetType};
use crate::assets::structs::{ParsedAsset, PendingAsset, StoreStats};
use crate::net::connection_manager::ConnectionContext;

#[async_trait]
pub trait StoreBase: Any + Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn dependencies(&self) -> &'static [TypeId];
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
    async fn load_assets(self: Arc<Self>, reader: &Arc<ZipReader>, pack: &str);
    async fn send_assets(&self, cx: &mut ConnectionContext);
}

pub struct AssetStore<T: AssetType> {
    assets: RwLock<HashMap<String, Asset<T>>>,

    children: RwLock<HashMap<String, HashSet<String>>>, // parent_id -> Set<child_ids>
    contained_in: RwLock<HashMap<String, HashSet<String>>>, // parent_id -> Set<contained_ids>
    orphans: RwLock<HashSet<String>>, // Which assets are orphans (parent not found)

    stats: RwLock<StoreStats>,
}

impl<T: AssetType + 'static + std::fmt::Debug> AssetStore<T> {
    pub fn new() -> Self {
        Self {
            assets: RwLock::new(HashMap::new()),
            children: RwLock::new(HashMap::new()),
            contained_in: RwLock::new(HashMap::new()),
            orphans: RwLock::new(HashSet::new()),
            stats: RwLock::new(StoreStats::default()),
        }
    }

    async fn decode_assets(self: Arc<Self>, pending: Vec<PendingAsset>, reader: &Arc<ZipReader>, pack: &str) {
        info!("Decoding {} assets of store {}", pending.len(), self.name());
        let start = Instant::now();
        let initial_len = pending.len();

        // STEP 1: Read and parse all files
        let parsed: Vec<ParsedAsset> = pending
            .into_par_iter()
            .filter_map(|asset| {
                match reader.read_file(&asset.path) {
                    Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                        Ok(json) => Some(ParsedAsset {
                            key: asset.key,
                            path: asset.path,
                            parent: json.get("Parent").and_then(|v| v.as_str()).map(String::from),
                            value: json,
                        }),
                        Err(err) => {
                            warn!("Failed to parse asset file {}: {}", asset.path, err);
                            None
                        }
                    },
                    Err(err) => {
                        warn!("Failed to read asset file {}: {}", asset.path, err);
                        None
                    }
                }
            })
            .collect();


        self.stats.write().failed += initial_len - parsed.len();

        // STEP 2: Process parent-child relationships
        let mut ready_assets: HashMap<String, (String, Value)> = HashMap::new();
        let mut waiting_queue: VecDeque<ParsedAsset> = VecDeque::new();

        for asset in parsed {
            if asset.parent.is_none() {
                ready_assets.insert(asset.key, (asset.path, asset.value));
            } else {
                waiting_queue.push_back(asset);
            }
        }

        // STEP 3: Merge parent-child JSON
        while !waiting_queue.is_empty() {
            let initial_len = waiting_queue.len();
            let mut still_waiting = VecDeque::new();

            while let Some(asset) = waiting_queue.pop_front() {
                let parent_key = asset.parent.as_ref().unwrap();

                if let Some((_, parent_value)) = ready_assets.get(parent_key) {
                    let merged = merge_json(parent_value, &asset.value);
                    ready_assets.insert(asset.key, (asset.path, merged));
                } else {
                    still_waiting.push_back(asset);
                }
            }

            // Check for progress
            if still_waiting.len() == initial_len {
                let missing: Vec<String> = still_waiting
                    .iter()
                    .map(|a| format!("{} (needs {})", a.key, a.parent.as_ref().unwrap()))
                    .collect();

                warn!("Unresolved {} asset parent dependencies: {}", still_waiting.len(), missing.join(", "));

                for asset in still_waiting {
                    self.orphans.write().insert(asset.key);
                    self.stats.write().failed += 1;
                }
                break;
            }

            waiting_queue = still_waiting;
        }

        let (valid_assets, failed_count): (Vec<_>, Vec<_>) = ready_assets
            .into_par_iter()
            .partition_map(|(id, (path, json))| {
                match serde_json::from_value::<T>(json) {
                    Ok(mut asset) => {
                        asset.set_id(id.clone());
                        Either::Left((id, path, asset))
                    }
                    Err(err) => {
                        warn!("Failed to deserialize asset {}: {}", id, err);
                        Either::Right(())
                    }
                }
            });

        let valid_assets_len = valid_assets.len();
        self.stats.write().loaded += valid_assets_len;
        self.stats.write().failed += failed_count.len();

        let mut assets_lock = self.assets.write();
        for (id, path, asset) in valid_assets {
            assets_lock.insert(id, Asset::new(asset, pack.to_owned(), path));
        }

        info!("Decoded {}/{} assets of store {} in {:.2?}", valid_assets_len, initial_len, self.name(), start.elapsed());
        self.print_stats();
    }

    pub fn print_stats(&self) {
        let stats = self.stats.read();
        info!(
            "Store {} Stats: Loaded: {}, Failed: {}, Orphans: {}",
            self.name(),
            stats.loaded,
            stats.failed,
            stats.orphans
        );
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

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    async fn load_assets(self: Arc<Self>, reader: &Arc<ZipReader>, pack: &str) {
        let store_path = format!("Server/{}", T::path());
        let paths: Vec<&String> = reader.iter(&store_path, T::extension()).collect();

        if paths.is_empty() {
            warn!("No assets found for {}", T::name());
            return;
        }

        let mut raw_assets = Vec::with_capacity(paths.len());
        for path in paths {
            match path.split('/').last().and_then(|s| s.strip_suffix(T::extension())) {
                Some(key) => raw_assets.push(PendingAsset {
                    key: key.to_owned(),
                    path: path.to_owned(),
                }),
                None => {
                    self.stats.write().failed += 1;
                    warn!("Invalid asset path: {}", path);
                }
            }
        }

        self.decode_assets(raw_assets, &reader, pack).await;
    }

    async fn send_assets(&self, cx: &mut ConnectionContext) {
        let packet = {
            let assets = self.assets.read();
            T::generate_init_packet(assets)
        };
        cx.send(packet).await;
    }
}

/// Merge child JSON into parent JSON recursively
/// - Objects: merge by key recursively
/// - Arrays: merge (no duplicates)
/// - Primitives: child wins
fn merge_json(parent: &Value, child: &Value) -> Value {
    match (parent, child) {
        (Value::Object(parent_obj), Value::Object(child_obj)) => {
            let mut merged = parent_obj.clone();

            for (key, child_val) in child_obj {
                if let Some(parent_val) = merged.get_mut(key) {
                    // Key exists in both - merge recursively
                    *parent_val = merge_json(parent_val, child_val);
                } else {
                    // Key only in child - add it
                    merged.insert(key.clone(), child_val.clone());
                }
            }

            Value::Object(merged)
        }
        (Value::Array(parent_arr), Value::Array(child_arr)) => {
            let mut merged = parent_arr.clone();

            for child_elem in child_arr {
                // Add if not already present
                if !merged.iter().any(|existing| existing == child_elem) {
                    merged.push(child_elem.clone());
                }
            }

            Value::Array(merged)
        }
        _ => child.clone(),
    }
}
