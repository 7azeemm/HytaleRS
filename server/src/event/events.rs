pub mod load_asset_event;

use crate::event::event_bus::Event;

pub struct LoadAssetEvent {}

impl Event for LoadAssetEvent {}