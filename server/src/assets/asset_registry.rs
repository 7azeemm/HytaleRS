use crate::assets::asset_store::{AssetStore, StoreBase};
use crate::assets::asset_type::AssetType;
use crate::assets::types::block_set::block_set::BlockSet;
use crate::net::connection_manager::ConnectionContext;
use log::info;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;
use crate::assets::types::block_particle::block_particle_set::BlockParticleSet;

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

    pub async fn register_stores(&self) {
        self.register::<BlockSet>().await;
        self.register::<BlockParticleSet>().await;
    }

    pub async fn register<T: AssetType + 'static>(&self) {
        let store = Arc::new(AssetStore::<T>::new());
        let name = store.name();
        self.stores.write().await.insert(store.type_id(), store);

        info!("Registered asset type: {} (path: {})", name, T::path());
    }

    pub async fn send_assets(&self, cx: &mut ConnectionContext) {
        for store in self.stores.read().await.values() {
            store.send_assets(cx).await;
        }
    }

    pub async fn get_all_stores(&self) -> Vec<Arc<dyn StoreBase>> {
        self.stores.read().await.values().cloned().collect()
    }

    pub async fn get<T: AssetType + 'static>(&self) -> Option<Arc<AssetStore<T>>> {
        self.stores
            .read()
            .await
            .get(&TypeId::of::<T>())
            .cloned()
            .and_then(|store| store.as_any_arc().downcast::<AssetStore<T>>().ok())
    }
}
