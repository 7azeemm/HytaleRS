use std::sync::LazyLock;
use tokio::sync::RwLock;
use crate::assets::asset_module::ASSET_MODULE;
use crate::event::event_bus::EVENT_BUS;
use crate::event::events::load_asset_event::LoadAssetEvent;

pub static COMMON_ASSET_MODULE: LazyLock<CommonAssetModule> = LazyLock::new(|| CommonAssetModule::new());

pub struct CommonAssetModule {
}

impl CommonAssetModule {
    fn new() -> Self {
        Self {
        }
    }

    pub async fn init(&self) {
        EVENT_BUS.on_async(None, |event: &LoadAssetEvent| async {
            for pack in ASSET_MODULE.asset_packs.read().await.iter() {
                pack.load_common_assets_index_hashes().await;
            }
        });
    }
}