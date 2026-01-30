use std::any::{Any, TypeId};
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use parking_lot::RwLock;
use log::{info, warn, error};
use once_cell::sync::OnceCell;
use serde::de::DeserializeOwned;
use crate::server::core::assets::asset_pack::{debug_virtual, AssetPack, VirtualPath};
use crate::server::core::assets::asset_store::{AssetStore, TypedAssetStore};
use crate::server::core::assets::types::block_set::block_set::BlockSet;

static ASSET_REGISTRY: OnceCell<AssetRegistry> = OnceCell::new();

#[derive(Debug)]
pub struct AssetRegistry {
    pub stores: RwLock<Vec<Arc<dyn AssetStore>>>,
}

impl AssetRegistry {
    pub fn init() {
        ASSET_REGISTRY.set(Self {
            stores: RwLock::new(Vec::new()),
        }).expect("Failed to init asset registry");
        
        register_stores();
    }

    pub fn register(&self, store: Arc<dyn AssetStore>) {
        info!("Registered asset store: {}", store.type_name());
        self.stores.write().push(store);
    }

    pub fn get() -> &'static AssetRegistry {
        ASSET_REGISTRY.get().unwrap()
    }
}

pub fn load_assets(asset_pack: &AssetPack) -> bool {
    let server_root = asset_pack.root.resolve("Server");
    info!("Loading assets from {:?}", debug_virtual(&server_root));

    let stores = AssetRegistry::get().stores.read();
    for store in stores.iter() {
        let path = store.path();

        let assets_path = match &server_root {
            VirtualPath::Directory(dir) => {
                VirtualPath::Directory(dir.join(path))
            }
            VirtualPath::Zip { zip, prefix } => {
                VirtualPath::Zip {
                    zip: zip.clone(),
                    prefix: format!("{}/{}", prefix.trim_end_matches('/'), path),
                }
            }
        };

        if !assets_path.is_dir() {
            continue;
        }

        let store_failed = store.load_from_directory(
            &asset_pack.name,
            &assets_path,
        );

        info!("{:#?}", store_failed.loaded)
    }

    true
}

pub fn register_stores() {
    let registry = AssetRegistry::get();
    registry.register(Arc::new(TypedAssetStore::<BlockSet>::new("BlockSet", "Item/Block/Sets", ".json")))
}