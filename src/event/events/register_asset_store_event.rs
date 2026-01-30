use crate::event::event_bus::Event;
use crate::server::core::assets::asset_store::AssetStore;
use std::any::TypeId;
use std::sync::Arc;

pub struct RegisterAssetStoreEvent {
    pub store: Arc<dyn AssetStore>,
}

impl Event for RegisterAssetStoreEvent {}
