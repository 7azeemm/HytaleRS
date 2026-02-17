use crate::assets::asset_reader::ZipReader;
use crate::assets::asset_registry::STORE_REGISTRY;
use crate::assets::asset_store::StoreBase;
use crate::assets::common::common_asset::FileCommonAsset;
use crate::assets::common::common_asset_registry::COMMON_ASSET_REGISTRY;
use crate::assets::errors::{AssetError, AssetResult};
use crate::plugin::plugin_manifest::PluginManifest;
use ahash::{HashMap, HashMapExt, HashSetExt};
use log::{info, warn};
use std::any::{Any, TypeId};
use std::collections::VecDeque;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use parking_lot::Mutex;
use crate::assets::structs::StoreStats;

pub struct AssetPack {
    name: String,
    path: PathBuf,
    reader: Arc<ZipReader>,
    manifest: PluginManifest,
    immutable: bool,
}

impl AssetPack {
    pub async fn load_pack(path: &PathBuf) -> AssetResult<Self> {
        let start_time = Instant::now();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| "Pack file does not have a name".to_string())?;

        info!("Loading Asset Pack {}", file_name);

        let reader = ZipReader::open(path, file_name)?;

        let manifest = serde_json::from_slice::<PluginManifest>(
            &reader.read_file("manifest.json")?,
        )
        .map_err(|err| AssetError::IoError(format!("Failed to parse pack manifest: {}", err)))?;

        let immutable = file_name.ends_with(".zip") || file_name.ends_with(".jar");
        let name = format!("{}:{}", manifest.group, manifest.name);

        info!("Loaded Asset Pack {} in {:.2?}", name, start_time.elapsed());

        Ok(Self {
            name,
            path: path.clone(),
            reader: Arc::new(reader),
            manifest,
            immutable,
        })
    }

    pub async fn load_assets(&self) {
        let stores = sort_stores(STORE_REGISTRY.get_all_stores().await);
        let global_stats = Arc::new(Mutex::new(StoreStats::default()));

        for store in stores {
            info!("Loading Assets from {}", self.name);
            store.load_assets(&self.reader, &self.name, global_stats.clone()).await;
        }
        
        global_stats.lock().print("All Stores");
    }

    pub async fn load_common_assets_index_hashes(&self) {
        let start = Instant::now();

        // Try to read hashes file
        let content = match self
            .reader
            .read_file("CommonAssetsIndex.hashes")
            .and_then(|b| {
                str::from_utf8(&b)
                    .map(|s| s.to_string())
                    .map_err(|err| AssetError::IoError(err.to_string()))
            }) {
            Ok(s) => s,
            Err(err) => {
                log::error!(
                    "Failed to read CommonAssetsIndex.hashes in pack '{}': {}",
                    self.name,
                    err
                );
                return;
            }
        };

        let mut loaded_count = 0;

        for (line_number, line) in content.lines().enumerate() {
            let mut split = line.splitn(2, ' ');
            let hash = match split.next() {
                Some(h) if h.len() == 64 => h,
                _ => {
                    warn!(
                        "Corrupt line in CommonAssetsIndex.hashes:L{} '{}'",
                        line_number, line
                    );
                    continue;
                }
            };

            let name = match split.next() {
                Some(n) => n,
                None => {
                    warn!(
                        "Corrupt line in CommonAssetsIndex.hashes:L{} '{}'",
                        line_number, line
                    );
                    continue;
                }
            };

            let asset = FileCommonAsset {
                name: name.to_owned(),
                hash: hash.to_owned(),
                path: format!("Common/{}", name),
                pack: self.name.clone(),
            };

            COMMON_ASSET_REGISTRY.add_common_asset(asset);

            loaded_count += 1;
        }

        info!(
            "Took {:.2?} to load {} assets from CommonAssetsIndex.hashes file.",
            start.elapsed(),
            loaded_count
        );
    }
}

pub fn sort_stores(stores: Vec<Arc<dyn StoreBase>>) -> Vec<Arc<dyn StoreBase>> {
    let mut by_name: HashMap<&str, Arc<dyn StoreBase>> = HashMap::with_capacity(stores.len());
    let mut in_degree: HashMap<&str, usize> = HashMap::with_capacity(stores.len());
    let mut graph: HashMap<&str, Vec<&str>> = HashMap::with_capacity(stores.len());

    // Index stores and initialize in-degrees
    for store in &stores {
        let name = store.name();
        by_name.insert(name, Arc::clone(store));
        in_degree.insert(name, 0);
    }

    // Build dependency graph
    for store in &stores {
        let store_name = store.name();

        for &dep in store.dependencies() {
            if !by_name.contains_key(dep) {
                panic!("Store `{}` depends on missing store `{}`", store_name, dep);
            }

            *in_degree.get_mut(&store_name).unwrap() += 1;
            graph.entry(dep).or_default().push(store_name);
        }
    }

    // Kahn's algorithm
    let mut queue: VecDeque<_> = in_degree
        .iter()
        .filter_map(|(&name, &deg)| if deg == 0 { Some(name) } else { None })
        .collect();

    let mut result = Vec::with_capacity(stores.len());

    while let Some(name) = queue.pop_front() {
        result.push(Arc::clone(&by_name[name]));

        if let Some(children) = graph.get(name) {
            for &child in children {
                *in_degree.get_mut(&child).unwrap() -= 1;
                if in_degree[child] == 0 {
                    queue.push_back(child);
                }
            }
        }
    }

    // Check for cycles
    if result.len() != stores.len() {
        panic!("Dependency cycle detected between asset stores");
    }

    result
}
