use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;
use crate::event::event_bus::EVENT_BUS;
use crate::event::events::load_asset_event::LoadAssetEvent;
use crate::assets::asset_pack::AssetPack;
use crate::server::core::options::Options;

pub static ASSET_MODULE: LazyLock<AssetModule> = LazyLock::new(|| AssetModule::new());

pub struct AssetModule {
    pub(crate) asset_packs: RwLock<Vec<AssetPack>>
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
            Ok(pack) => self.asset_packs.write().await.push(pack),
            Err(err) => panic!("Skipping Asset Pack at {}: {}", path.display(), err)
        }

        if self.asset_packs.read().await.is_empty() {
            panic!("No asset packs found!")
        }

        EVENT_BUS.on_async(None, |event: &LoadAssetEvent| async {
            // TODO: PreLoadAssets
        
            // Load Assets
            for pack in ASSET_MODULE.asset_packs.read().await.iter() {
                pack.load_assets().await;
            }
        });
    }
}