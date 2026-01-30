use std::sync::{Arc, LazyLock};
use log::{error, info};
use parking_lot::Mutex;
use crate::event::event_bus::EVENT_BUS;
use crate::event::events::asset_pack_register_event::AssetPackRegisterEvent;
use crate::event::events::asset_pack_unregister_event::AssetPackUnregisterEvent;
use crate::event::events::load_asset_event::LoadAssetEvent;
use crate::event::events::register_asset_store_event::RegisterAssetStoreEvent;
use crate::event::events::remove_asset_store_event::RemoveAssetStoreEvent;
use crate::server::core::assets::asset_pack::AssetPack;
use crate::server::core::assets::asset_registry::{load_assets, AssetRegistry};
use crate::server::core::assets::pack_loader::load_pack;
use crate::server::core::options::Options;

pub static ASSET_MODULE: LazyLock<AssetModule> = LazyLock::new(|| AssetModule::new());

pub struct AssetModule {
    pub packs: Mutex<Vec<Arc<AssetPack>>>
}

impl AssetModule {
    fn new() -> Self {
        Self { packs: Mutex::new(Vec::new()) }
    }

    pub async fn init(&self) {
        let path = &Options::get().assets;
        if let Some(pack) = load_pack(&path).await {
            self.packs.lock().push(Arc::new(pack));
        };

        // TODO: load packs from other dirs

        if self.packs.lock().is_empty() {
            panic!("No asset packs found!")
        }

        EVENT_BUS.on(None, |event: &LoadAssetEvent| {
            // PreLoadAssets

            // Load Assets
            let packs = ASSET_MODULE.packs.lock();
            for pack in packs.iter() {
                let i = load_assets(pack);
            }
        });

        // Register handler for AssetPackRegisterEvent (priority -16)
        EVENT_BUS.on(Some(16), |event: &AssetPackRegisterEvent| {
            info!("Registering asset pack: {}", event.pack.name);
            
            let mut packs = ASSET_MODULE.packs.lock();
            packs.push(event.pack.clone());
            
            // Reload assets from all packs
            for pack in packs.iter() {
                load_assets(pack);
            }
        });

        // Register handler for AssetPackUnregisterEvent
        EVENT_BUS.on(None, |event: &AssetPackUnregisterEvent| {
            info!("Unregistering asset pack: {}", event.pack_name);
            
            let mut packs = ASSET_MODULE.packs.lock();
            
            // Remove pack from list
            packs.retain(|p| p.name != event.pack_name);
            
            // Remove all assets from this pack from stores
            let registry = AssetRegistry::get();
            let stores = registry.stores.read();
            for store in stores.iter() {
                // Note: We need to add remove_pack method to AssetStore trait
                // For now, just log that we would remove assets
                info!("Would remove assets from pack '{}' from store '{}'", event.pack_name, store.name());
            }
        });

        // Register handler for RegisterAssetStoreEvent
        EVENT_BUS.on(None, |event: &RegisterAssetStoreEvent| {
            info!("Registering asset store: {}", event.store.type_name());
            
            AssetRegistry::get().register(event.store.clone());
            
            // Load assets for this store from all existing packs
            let packs = ASSET_MODULE.packs.lock();
            for pack in packs.iter() {
                let server_root = pack.root.resolve("Server");
                let assets_path = server_root.join(event.store.path());
                
                if assets_path.is_dir() {
                    event.store.load_from_directory(&pack.name, &assets_path);
                }
            }
        });

        // Register handler for RemoveAssetStoreEvent
        EVENT_BUS.on(None, |event: &RemoveAssetStoreEvent| {
            info!("Removing asset store with type ID: {:?}", event.store_type_id);
            
            let registry = AssetRegistry::get();
            let mut stores = registry.stores.write();
            
            // Remove store by type ID
            let initial_count = stores.len();
            stores.retain(|s| s.type_id() != event.store_type_id);
            let removed_count = initial_count - stores.len();
            
            info!("Removed {} asset store(s)", removed_count);
        });
    }
}