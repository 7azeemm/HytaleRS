use std::collections::HashMap;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::objects::objects::{ColorLight, Direction, HitBox, RangeFloat, Vec3f};
use crate::packets::assets::entity_effect::Animation;
use crate::packets::assets::interactions::interaction_type::InteractionType;
use crate::packets::assets::item::ModelTrail;
use crate::packets::assets::item_animations::CameraSettingsPacket;
use crate::packets::assets::model_particle::ModelParticlePacket;
use crate::packets::assets::update_type::UpdateType;

#[packet(id = 85, max_size = 0x64000000, compressed)]
pub struct UpdateProjectileConfigs {
    pub update_type: UpdateType,
    pub configs: HashMap<String, ProjectileConfigPacket>,
    pub removed_configs: Vec<String>
}

#[packet_field]
pub struct ProjectileConfigPacket {
    pub physics_config: FixedOption<PhysicsConfig>,
    pub launch_force: f64,
    pub spawn_offset: FixedOption<Vec3f>,
    pub rotation_offset: FixedOption<Direction>,
    pub launch_local_sound_event_index: i32,
    pub launch_world_sound_event_index: i32,
    pub projectile_sound_event_index: i32,
    pub interactions: HashMap<InteractionType, i32>,
    pub model: Option<Model>,
}

#[packet_field]
pub struct PhysicsConfig {
    pub physics_type: PhysicsType,
    pub density: bool,
    pub gravity: bool,
    pub bounciness: bool,
    pub bounce_count: i32,
    pub bounce_limit: f64,
    pub sticks_vertically: bool,
    pub compute_yaw: bool,
    pub compute_pitch: bool,
    pub rotation_mode: RotationMode,
    pub move_out_of_solid_speed: f64,
    pub terminal_velocity_air: f64,
    pub density_air: f64,
    pub terminal_velocity_water: f64,
    pub density_water: f64,
    pub hit_water_impulse_loss: f64,
    pub rotation_force: f64,
    pub speed_rotation_factor: f32,
    pub swimming_damping_factor: f64,
    pub allow_rolling: bool,
    pub rolling_friction_factor: f64,
    pub rolling_speed: f32
}

#[packet_field]
pub struct Model {
    pub scale: f32,
    pub eye_height: f32,
    pub crouch_offset: f32,
    pub sitting_offset: f32,
    pub sleeping_offset: f32,
    pub hitbox: FixedOption<HitBox>,
    pub light: FixedOption<ColorLight>,
    pub phobia: Phobia,
    pub asset_id: Option<String>,
    pub path: Option<String>,
    pub texture: Option<String>,
    pub gradient_set: Option<String>,
    pub gradient_id: Option<String>,
    pub camera: Option<CameraSettingsPacket>,
    pub animation_sets: HashMap<String, AnimationSet>,
    pub attachments: Vec<ModelAttachment>,
    pub particles: Vec<ModelParticlePacket>,
    pub trails: Vec<ModelTrail>,
    pub detail_boxes: HashMap<String, Vec<DetailBox>>,
    pub phobia_model: Option<Box<Model>>
}

#[packet_field]
pub struct DetailBox {
    pub offset: FixedOption<Vec3f>,
    pub hitbox: FixedOption<HitBox>
}

#[packet_enum]
pub enum Phobia {
    None,
    Arachnophobia,
    Ophidiophobia
}

#[packet_field]
pub struct AnimationSet {
    pub next_animation_delay: FixedOption<RangeFloat>,
    pub id: Option<String>,
    pub animations: Vec<Animation>,
}

#[packet_field]
pub struct ModelAttachment {
    pub model: Option<String>,
    pub texture: Option<String>,
    pub gradient_set: Option<String>,
    pub gradient_id: Option<String>
}

#[packet_enum]
pub enum PhysicsType {
    Standard
}

#[packet_enum]
pub enum RotationMode {
    None,
    Velocity,
    VelocityDamped,
    VelocityRoll
}