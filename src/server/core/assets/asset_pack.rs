use std::any::{Any, TypeId};
use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use log::{error, info};
use zip::ZipArchive;
use crate::plugin::plugin_manifest::PluginManifest;
use crate::server::core::assets::asset_reader::ZipReader;
use crate::server::core::assets::{AssetError, AssetResult};
use crate::server::core::assets::asset_registry::STORE_REGISTRY;
use crate::server::core::assets::asset_store::StoreBase;

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

        let mut reader = ZipReader::open(path, file_name)?;

        let manifest = serde_json::from_slice::<PluginManifest>(&reader.read_file("manifest.json")?)
            .map_err(|err| AssetError::IoError(format!("Failed to parse pack manifest: {}", err)))?;

        let immutable = file_name.ends_with(".zip") || file_name.ends_with(".jar");
        let name = format!("{}:{}", manifest.group, manifest.name);

        info!("Loaded Asset Pack {} in {:.2?}", name, start_time.elapsed());

        Ok(Self {
            name,
            path: path.clone(),
            reader: Arc::new(reader),
            manifest,
            immutable
        })
    }

    pub async fn load_assets(&self) {
        let stores = sort_stores(STORE_REGISTRY.get_all_stores());

        for store in stores {
            info!("Loading Assets from {}", self.name);
            store.load_assets(&self.reader).await;
        }
    }
}

pub fn sort_stores(stores: Vec<Arc<dyn StoreBase>>) -> Vec<Arc<dyn StoreBase>> {
    let mut by_type: HashMap<TypeId, Arc<dyn StoreBase>> = HashMap::with_capacity(stores.len());
    let mut in_degree: HashMap<TypeId, usize> = HashMap::with_capacity(stores.len());
    let mut graph: HashMap<TypeId, Vec<TypeId>> = HashMap::with_capacity(stores.len());

    // Index stores and initialize in-degrees
    for store in &stores {
        let ty = store.type_id();
        by_type.insert(ty, Arc::clone(store));
        in_degree.insert(ty, 0);
    }

    // Build dependency graph
    for store in &stores {
        let store_ty = store.type_id();

        for &dep in store.dependencies() {
            if !by_type.contains_key(&dep) {
                panic!("Store `{}` depends on missing store {:?}", store.name(), dep);
            }

            *in_degree.get_mut(&store_ty).unwrap() += 1;
            graph.entry(dep).or_default().push(store_ty);
        }
    }

    // Kahn's algorithm
    let mut queue: VecDeque<_> = in_degree
        .iter()
        .filter_map(|(&ty, &deg)| if deg == 0 { Some(ty) } else { None })
        .collect();

    let mut result = Vec::with_capacity(stores.len());

    while let Some(ty) = queue.pop_front() {
        result.push(Arc::clone(&by_type[&ty]));

        if let Some(children) = graph.get(&ty) {
            for &child in children {
                *in_degree.get_mut(&child).unwrap() -= 1;
                if in_degree[&child] == 0 {
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