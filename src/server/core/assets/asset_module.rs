use std::sync::{Arc, LazyLock};
use parking_lot::RwLock;
use crate::event::event_bus::EVENT_BUS;
use crate::event::events::load_asset_event::LoadAssetEvent;
use crate::server::core::assets::asset_pack::AssetPack;
use crate::server::core::options::Options;

pub static ASSET_MODULE: LazyLock<AssetModule> = LazyLock::new(|| AssetModule::new());

pub struct AssetModule {
    asset_packs: RwLock<Vec<AssetPack>>
}

impl AssetModule {
    fn new() -> Self {
        Self {
            asset_packs: RwLock::new(Vec::new())
        }
    }

    pub async fn init(&self) {
        let path = &Options::get().assets;
        
        match AssetPack::load_pack(path).await {
            Ok(pack) => self.asset_packs.write().push(pack),
            Err(err) => panic!("Skipping Asset Pack at {}: {}", path.display(), err)
        }

        if self.asset_packs.read().is_empty() {
            panic!("No asset packs found!")
        }

        EVENT_BUS.on(None, |event: &LoadAssetEvent| {
            // PreLoadAssets
        
            // Load Assets
            for pack in ASSET_MODULE.asset_packs.read().iter() {
                pack.load_assets();
            }
        });
    }
}