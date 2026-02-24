use serde::{Deserialize, Serialize};
use protocol::objects::objects::{Color, Direction, Vec3f};
use protocol::packets::assets::model_particle::EntityPart;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ModelParticle {
    pub system_id: Option<String>,
    pub target_entity_part: EntityPart,
    pub target_node_name: Option<String>,
    pub color: Option<Color>,
    pub scale: f32,
    pub position_offset: Option<Vec3f>,
    pub rotation_offset: Option<Direction>,
    pub detached_from_model: bool
}

impl Default for ModelParticle {
    fn default() -> Self {
        Self {
            system_id: None,
            target_entity_part: EntityPart::SelfPart,
            target_node_name: None,
            color: None,
            scale: 1.0,
            position_offset: None,
            rotation_offset: None,
            detached_from_model: false
        }
    }
}