use std::any::TypeId;
use serde::{Deserialize, Serialize};

pub trait AssetType: Serialize + for<'de> Deserialize<'de> + Send + Sync + Sized + Clone + 'static {
    fn name() -> &'static str;
    fn path() -> &'static str;
    fn id(&self) -> &str;
    fn set_id(&mut self, id: String);
    fn parent(&self) -> Option<&str> { None }
    fn dependencies() -> &'static [TypeId] { &[] }
    fn extension() -> &'static str { ".json" }
}

#[derive(Clone)]
pub struct Asset<T: AssetType> {
    pub data: T,
    pub from_pack: String,
    pub from_path: String,
}

impl<T: AssetType> Asset<T> {
    pub fn new(asset: T, from_pack: &str, from_path: &str) -> Self {
        Self {
            data: asset,
            from_pack: from_pack.to_string(),
            from_path: from_path.to_string(),
        }
    }
}
