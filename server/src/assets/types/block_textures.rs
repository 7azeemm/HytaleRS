use serde::{Deserialize, Serialize};
use protocol::packets::assets::block_textures::BlockTexturesPacket;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct BlockTextures {
    pub up: String,
    pub down: String,
    pub north: String,
    pub south: String,
    pub east: String,
    pub west: String,
    pub weight: i32
}

impl Default for BlockTextures {
    fn default() -> Self {
        Self {
            up: "BlockTextures/Unknown.png".to_owned(),
            down: "BlockTextures/Unknown.png".to_owned(),
            north: "BlockTextures/Unknown.png".to_owned(),
            south: "BlockTextures/Unknown.png".to_owned(),
            east: "BlockTextures/Unknown.png".to_owned(),
            west: "BlockTextures/Unknown.png".to_owned(),
            weight: 1
        }
    }
}

impl BlockTextures {
    pub fn to_packet(&self, total_weight: f32) -> BlockTexturesPacket {
        BlockTexturesPacket {
            weight: self.weight as f32 / total_weight,
            up: Some(self.up.clone()),//TODO: search for a way to make packets without cloning
            down: Some(self.down.clone()),
            south: Some(self.south.clone()),
            north: Some(self.north.clone()),
            west: Some(self.west.clone()),
            east: Some(self.east.clone()),
        }
    }
}