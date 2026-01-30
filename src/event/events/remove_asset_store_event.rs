use crate::event::event_bus::Event;
use std::any::TypeId;

pub struct RemoveAssetStoreEvent {
    pub store_type_id: TypeId,
}

impl Event for RemoveAssetStoreEvent {}
