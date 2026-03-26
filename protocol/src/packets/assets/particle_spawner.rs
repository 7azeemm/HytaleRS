use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{Color, Range, RangeFloat, RangeVec2f, RangeVec3f, Size, Vec3f};
use crate::packets::assets::fx_render_mode::FXRenderMode;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 50, max_size = 0x64000000, compressed)]
pub struct UpdateParticleSpawners {
    pub update_type: UpdateType,
    pub particle_spawners: HashMap<String, ParticleSpawnerPacket>,
    pub removed_particle_spawners: Vec<String>
}

#[packet_field]
pub struct ParticleSpawnerPacket {
    pub shape: EmitShape,
    pub emit_offset: FixedOption<RangeVec3f>,
    pub camera_offset: f32,
    pub use_emit_direction: bool,
    pub life_span: f32,
    pub spawn_rate: FixedOption<RangeFloat>,
    pub spawn_burst: bool,
    pub wave_delay: FixedOption<RangeFloat>,
    pub total_particles: FixedOption<Range>,
    pub max_concurrent_particles: i32,
    pub initial_velocity: FixedOption<InitialVelocity>,
    pub velocity_stretch_multiplier: f32,
    pub particle_rotation_influence: ParticleRotationInfluence,
    pub particle_rotate_with_spawner: bool,
    pub is_low_res: bool,
    pub trail_spawner_position_multiplier: f32,
    pub trait_spawner_rotation_multiplier: f32,
    pub particle_collision: FixedOption<ParticleCollisionPacket>,
    pub render_mode: FXRenderMode,
    pub light_influence: f32,
    pub linear_filtering: bool,
    pub particle_life_span: FixedOption<RangeFloat>,
    pub intersection_highlight: FixedOption<IntersectionHighlightPacket>,
    pub id: Option<String>,
    pub particle: Option<ParticlePacket>,
    pub uv_motion: Option<UVMotionPacket>,
    pub attractors: Vec<ParticleAttractorPacket>,
}

#[packet_field]
pub struct ParticlePacket {
    pub frame_size: FixedOption<Size>,
    pub uv_option: ParticleUVOption,
    pub scale_ratio_constraint: ParticleScaleRatioConstraint,
    pub soft_particles: SoftParticle,
    pub soft_particles_fade_factor: f32,
    pub use_sprite_blending: bool,
    pub initial_animation_frame: FixedOption<ParticleAnimationFramePacket>,
    pub collision_animation_frame: FixedOption<ParticleAnimationFramePacket>,
    pub texture_path: Option<String>,
    pub animation_frames: HashMap<i32, ParticleAnimationFramePacket>
}

#[packet_field]
pub struct ParticleAnimationFramePacket {
    pub frame_index: FixedOption<Range>,
    pub scale: FixedOption<RangeVec2f>,
    pub rotation: FixedOption<RangeVec3f>,
    pub color: FixedOption<Color>,
    pub opacity: f32,
}

#[packet_field]
pub struct ParticleAttractorPacket {
    pub position: FixedOption<Vec3f>,
    pub radial_axis: FixedOption<Vec3f>,
    pub trail_position_multiplier: f32,
    pub radius: f32,
    pub radial_acceleration: f32,
    pub radial_tangent_acceleration: f32,
    pub linear_acceleration: FixedOption<Vec3f>,
    pub radial_impulse: f32,
    pub radial_tangent_impulse: f32,
    pub linear_impulse: FixedOption<Vec3f>,
    pub damping_multiplier: FixedOption<Vec3f>
}

#[packet_field]
pub struct ParticleCollisionPacket {
    pub block_type: ParticleCollisionBlockType,
    pub action: ParticleCollisionAction,
    pub particle_rotation_influence: ParticleRotationInfluence,
}

#[packet_field]
pub struct UVMotionPacket {
    pub add_random_uv_offset: bool,
    pub speed_x: f32,
    pub speed_y: f32,
    pub scale: f32,
    pub strength: f32,
    pub strength_curve_type: UVMotionCurveType,
    pub texture: Option<String>
}

#[packet_field]
pub struct IntersectionHighlightPacket {
    pub highlight_threshold: f32,
    pub highlight_color: FixedOption<Color>
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
#[packet_field]
pub struct InitialVelocity {
    pub yaw: FixedOption<RangeFloat>,
    pub pitch: FixedOption<RangeFloat>,
    pub speed: FixedOption<RangeFloat>,
}

#[packet_enum]
pub enum EmitShape {
    Sphere,
    Cube
}

#[packet_enum]
pub enum ParticleCollisionBlockType {
    None,
    Air,
    Solid,
    All
}

#[packet_enum]
pub enum ParticleCollisionAction {
    Expire,
    LastFrame,
    Linger
}

#[packet_enum]
pub enum ParticleRotationInfluence {
    None,
    Billboard,
    BillboardY,
    BillboardVelocity,
    Velocity
}

#[packet_enum]
pub enum UVMotionCurveType {
    Constant,
    IncreaseLinear,
    IncreaseQuartIn,
    IncreaseQuartInOut,
    IncreaseQuartOut,
    DecreaseLinear,
    DecreaseQuartIn,
    DecreaseQuartInOut,
    DecreaseQuartOut,
}

#[packet_enum]
pub enum ParticleUVOption {
    None,
    RandomFlipU,
    RandomFlipV,
    RandomFlipUV,
    FlipU,
    FlipV,
    FlipUV
}

#[packet_enum]
pub enum ParticleScaleRatioConstraint {
    OneToOne,
    Preserved,
    None
}

#[packet_enum]
pub enum SoftParticle {
    Enable,
    Disable,
    Require
}
