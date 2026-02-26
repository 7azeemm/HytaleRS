use macros::packet_enum;

#[packet_enum]
pub enum FXRenderMode {
    BlendLinear,
    BlendAdd,
    Erosion,
    Distortion
}