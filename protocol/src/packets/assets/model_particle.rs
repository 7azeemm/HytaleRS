use macros::{packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, Direction, Vec3f};

#[packet_field]
pub struct ModelParticlePacket {
    pub scale: f32,
    pub color: FixedOption<Color>,
    pub target_entity_part: EntityPart,
    pub position_offset: FixedOption<Vec3f>,
    pub rotation_offset: FixedOption<Direction>,
    pub detached_from_model: bool,
    pub system_id: Option<String>,
    pub target_node_name: Option<String>,
}

#[packet_enum]
pub enum EntityPart {
    SelfPart,
    Entity,
    PrimaryItem,
    SecondaryItem
}