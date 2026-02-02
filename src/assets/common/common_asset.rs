use crate::protocol::packets::setup::asset::Asset;

pub struct FileCommonAsset {
    pub name: String,
    pub hash: String,
    pub path: String,
    pub pack: String,
}

impl FileCommonAsset {
    pub fn to_packet(&self) -> Asset {
        Asset {
            name: self.name.clone(),
            hash: self.hash.clone(),
        }
    }
}