use macros::packet_enum;

#[packet_enum]
pub enum ShaderType {
    None,
    Wind,
    WindAttached,
    WindRandom,
    WindFractal,
    Ice,
    Water,
    Lava,
    Slime,
    Ripple
}