use macros::packet_field;

#[packet_field]
pub struct BlockTexturesPacket {
    pub weight: f32,
    pub up: Option<String>,
    pub down: Option<String>,
    pub south: Option<String>,
    pub north: Option<String>,
    pub west: Option<String>,
    pub east: Option<String>,
}