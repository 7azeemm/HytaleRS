use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use log::{info, warn};
use parking_lot::RwLock;
use crate::asset_store::{AssetStore, StoreBase};
use crate::asset_type::AssetType;
use crate::types::block_set::block_set::BlockSet;

pub static STORE_REGISTRY: LazyLock<StoreRegistry> = LazyLock::new(|| StoreRegistry::new());

pub struct StoreRegistry {
    stores: RwLock<HashMap<TypeId, Arc<dyn StoreBase>>>,
}

impl StoreRegistry {
    pub fn new() -> Self {
        Self {
            stores: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_stores(&self) {
        self.register::<BlockSet>();
    }

    pub fn register<T: AssetType + 'static>(&self) {
        let store = Arc::new(AssetStore::<T>::new());
        let name = store.name();
        self.stores.write().insert(store.type_id(), store);

        info!("Registered asset type: {} (path: {})", name, T::path());
    }

    pub fn get_all_stores(&self) -> Vec<Arc<dyn StoreBase>> {
        self.stores.read().values().cloned().collect()
    }

    pub fn get<T: AssetType + 'static>(&self) -> Option<Arc<AssetStore<T>>> {
        self.stores
            .read()
            .get(&TypeId::of::<T>())
            .cloned()
            .and_then(|store| {
                store.as_any_arc()
                    .downcast::<AssetStore<T>>()
                    .ok()
            })
    }
}
