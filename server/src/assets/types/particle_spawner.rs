use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::FixedOption;
use protocol::objects::objects::{Color, Range, RangeFloat, RangeVec2f, RangeVec3f, Size, Vec3f};
use protocol::packets::assets::fx_render_mode::FXRenderMode;
use protocol::packets::assets::particle_spawner::{EmitShape, InitialVelocity, IntersectionHighlight, ParticleAnimationFramePacket, ParticleAttractorPacket, ParticleCollisionAction, ParticleCollisionBlockType, ParticleCollisionPacket, ParticlePacket, ParticleRotationInfluence, ParticleScaleRatioConstraint, ParticleSpawnerPacket, ParticleUVOption, SoftParticle, UVMotionCurveType, UVMotionPacket, UpdateParticleSpawners};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ParticleSpawner {
    pub id: String,
    pub parent: Option<String>,
    pub render_mode: FXRenderMode,
    pub shape: EmitShape,
    pub emit_offset: RangeVec3f,
    pub camera_offset: f32,
    pub use_emit_direction: bool,
    pub life_span: f32,
    pub spawn_rate: Option<RangeFloat>,
    pub spawn_burst: bool,
    pub wave_delay: Option<RangeFloat>,
    pub total_particles: Range,
    pub max_concurrent_particles: i32,
    pub initial_velocity: InitialVelocity,
    pub velocity_stretch_multiplier: f32,
    pub particle_rotation_influence: ParticleRotationInfluence,
    pub particle_rotate_with_spawner: bool,
    pub is_low_res: bool,
    pub trail_spawner_position_multiplier: f32,
    pub trait_spawner_rotation_multiplier: f32,
    pub particle_collision: Option<ParticleCollision>,
    pub light_influence: f32,
    pub linear_filtering: bool,
    pub particle_life_span: Option<RangeFloat>,
    pub intersection_highlight: IntersectionHighlight,
    pub particle: Option<Particle>,
    #[serde(rename = "UVMotion")]
    pub uv_motion: UVMotion,
    pub attractors: Vec<ParticleAttractor>,
}

impl Default for ParticleSpawner {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            parent: None,
            render_mode: FXRenderMode::BlendLinear,
            shape: EmitShape::Sphere,
            emit_offset: Default::default(),
            camera_offset: 0.0,
            use_emit_direction: false,
            life_span: 0.0,
            spawn_rate: None,
            spawn_burst: false,
            wave_delay: None,
            total_particles: Default::default(),
            max_concurrent_particles: 0,
            initial_velocity: Default::default(),
            velocity_stretch_multiplier: 0.0,
            particle_rotation_influence: ParticleRotationInfluence::None,
            particle_rotate_with_spawner: false,
            is_low_res: false,
            trail_spawner_position_multiplier: 0.0,
            trait_spawner_rotation_multiplier: 0.0,
            particle_collision: None,
            light_influence: 0.0,
            linear_filtering: false,
            particle_life_span: None,
            intersection_highlight: IntersectionHighlight::default(),
            particle: None,
            uv_motion: UVMotion::default(),
            attractors: vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Particle {
    pub texture_path: Option<String>,
    pub frame_size: Option<Size>,
    #[serde(rename = "UVOption")]
    pub uv_option: ParticleUVOption,
    pub scale_ratio_constraint: ParticleScaleRatioConstraint,
    pub soft_particles: SoftParticle,
    pub soft_particles_fade_factor: f32,
    pub use_sprite_blending: bool,
    pub initial_animation_frame: Option<ParticleAnimationFrame>,
    pub collision_animation_frame: Option<ParticleAnimationFrame>,
    pub animation_frames: HashMap<i32, ParticleAnimationFrame>
}

impl Default for Particle {
    fn default() -> Self {
        Self {
            texture_path: None,
            frame_size: None,
            uv_option: ParticleUVOption::None,
            scale_ratio_constraint: ParticleScaleRatioConstraint::OneToOne,
            soft_particles: SoftParticle::Enable,
            soft_particles_fade_factor: 1.0,
            use_sprite_blending: false,
            initial_animation_frame: None,
            collision_animation_frame: None,
            animation_frames: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ParticleAnimationFrame {
    pub frame_index: Option<Range>,
    pub scale: Option<RangeVec2f>,
    pub rotation: Option<RangeVec3f>,
    pub color: Option<Color>,
    pub opacity: f32,
}

impl Default for ParticleAnimationFrame {
    fn default() -> Self {
        Self {
            frame_index: None,
            scale: None,
            rotation: None,
            color: None,
            opacity: -1.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ParticleAttractor {
    pub position: Option<Vec3f>,
    pub radial_axis: Option<Vec3f>,
    pub trail_position_multiplier: f32,
    pub radius: f32,
    pub radial_acceleration: f32,
    pub radial_tangent_acceleration: f32,
    pub linear_acceleration: Option<Vec3f>,
    pub radial_impulse: f32,
    pub radial_tangent_impulse: f32,
    pub linear_impulse: Option<Vec3f>,
    pub damping_multiplier: Option<Vec3f>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ParticleCollision {
    pub block_type: ParticleCollisionBlockType,
    pub action: ParticleCollisionAction,
    pub particle_rotation_influence: Option<ParticleRotationInfluence>,
}

impl Default for ParticleCollision {
    fn default() -> Self {
        Self {
            block_type: ParticleCollisionBlockType::None,
            action: ParticleCollisionAction::Expire,
            particle_rotation_influence: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct UVMotion {
    #[serde(rename = "AddRandomUVOffset")]
    pub add_random_uv_offset: bool,
    pub speed_x: f32,
    pub speed_y: f32,
    pub scale: f32,
    pub strength: f32,
    pub strength_curve_type: UVMotionCurveType,
    pub texture: Option<String>
}

impl Default for UVMotion {
    fn default() -> Self {
        Self {
            add_random_uv_offset: false,
            speed_x: 0.0,
            speed_y: 0.0,
            scale: 0.0,
            strength: 0.0,
            strength_curve_type: UVMotionCurveType::Constant,
            texture: None,
        }
    }
}

impl AssetType for ParticleSpawner {
    type InitPacketType = UpdateParticleSpawners;

    fn name() -> &'static str {
        "Particles"
    }

    fn path() -> &'static str {
        "Particles"
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    fn extension() -> &'static str {
        ".particlespawner"
    }

    fn generate_init_packet(map: RwLockReadGuard<RawRwLock, HashMap<String, Asset<Self>>>) -> Self::InitPacketType {
        let mut particle_spawners: HashMap<String, ParticleSpawnerPacket> = HashMap::default();

        for (id, asset) in map.iter() {
            let d = &asset.data;
            particle_spawners.insert(id.clone(), ParticleSpawnerPacket {
                shape: d.shape,
                emit_offset: FixedOption(d.emit_offset.clone().into()),
                camera_offset: d.camera_offset,
                use_emit_direction: d.use_emit_direction,
                life_span: d.life_span,
                spawn_rate: FixedOption(d.spawn_rate.clone()),
                spawn_burst: d.spawn_burst,
                wave_delay: FixedOption(d.wave_delay.clone()),
                total_particles: FixedOption(d.total_particles.clone().into()),
                max_concurrent_particles: d.max_concurrent_particles,
                initial_velocity: FixedOption(d.initial_velocity.clone().into()),
                velocity_stretch_multiplier: d.velocity_stretch_multiplier,
                particle_rotation_influence: d.particle_rotation_influence,
                particle_rotate_with_spawner: d.particle_rotate_with_spawner,
                is_low_res: d.is_low_res,
                trail_spawner_position_multiplier: d.trail_spawner_position_multiplier,
                trait_spawner_rotation_multiplier: d.trait_spawner_rotation_multiplier,
                particle_collision: FixedOption(ParticleCollisionPacket {
                    block_type: ParticleCollisionBlockType::None,
                    action: ParticleCollisionAction::Expire,
                    particle_rotation_influence: ParticleRotationInfluence::None,
                }.into()),
                render_mode: FXRenderMode::BlendLinear,
                light_influence: 0.0,
                linear_filtering: false,
                particle_life_span: FixedOption(RangeFloat::default().into()),
                intersection_highlight: FixedOption(IntersectionHighlight::default().into()),
                id: None, //Somehow when it is set, the client fails to deserialize the packet
                particle: None,
                uv_motion: None,
                attractors: vec![],
            });
        }

        UpdateParticleSpawners {
            update_type: UpdateType::Init,
            particle_spawners,
            removed_particle_spawners: Vec::new()
        }
    }
}
