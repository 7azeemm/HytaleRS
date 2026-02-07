use std::any::TypeId;
use std::collections::HashMap;
use std::fmt::Debug;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::packet::Packet;

pub trait AssetType: Serialize + for<'de> Deserialize<'de> + Send + Sync + Sized + Clone + Debug + 'static {
    type InitPacketType: Packet;

    fn name() -> &'static str;
    fn path() -> &'static str;
    fn id(&self) -> &str;
    fn set_id(&mut self, id: String);
    fn parent(&self) -> Option<&str> { None }
    fn dependencies() -> &'static [TypeId] { &[] }
    fn extension() -> &'static str { ".json" }
    fn generate_init_packet(map: RwLockReadGuard<RawRwLock, HashMap<String, Asset<Self>>>) -> Self::InitPacketType;
}

#[derive(Clone, Debug)]
pub struct Asset<T: AssetType> {
    pub data: T,
    pub from_pack: String,
    pub from_path: String,
}

impl<T: AssetType> Asset<T> {
    pub fn new(data: T, from_pack: String, from_path: String) -> Self {
        Self { data, from_pack, from_path }
    }
}
