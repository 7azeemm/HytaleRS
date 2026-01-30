use crate::event::event_bus::Event;
use crate::server::core::assets::asset_pack::AssetPack;
use std::sync::Arc;

pub struct AssetPackRegisterEvent {
    pub pack: Arc<AssetPack>,
}

impl Event for AssetPackRegisterEvent {}
