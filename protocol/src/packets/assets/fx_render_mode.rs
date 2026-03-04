use macros::packet_enum;

//TODO: auto impl first variant as default in packet_enum macro
#[derive(Default)]
#[packet_enum]
pub enum FXRenderMode {
    #[default]
    BlendLinear,
    BlendAdd,
    Erosion,
    Distortion
}