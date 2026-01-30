use crate::event::event_bus::Event;

pub struct AssetPackUnregisterEvent {
    pub pack_name: String,
}

impl Event for AssetPackUnregisterEvent {}
