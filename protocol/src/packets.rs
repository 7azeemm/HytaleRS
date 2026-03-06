pub mod assets;
pub mod connection;
pub mod setup;
pub mod builder_tools;
// TODO: default max_size
// TODO: Add necessary checks for packet codecs to avoid clients crashing the server, like list varint/size checks

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use crate::io::packet::Packet;
    use crate::packets::assets::fx_render_mode::FXRenderMode;
    use crate::packets::assets::particle_spawner::{EmitShape, ParticleRotationInfluence, ParticleSpawnerPacket, UpdateParticleSpawners};
    use crate::packets::assets::update_type::UpdateType;

    #[test]
    fn test_packet() {
        let mut map = HashMap::default();
        map.insert("test".to_owned(), ParticleSpawnerPacket {
            shape: EmitShape::Sphere,
            emit_offset: Default::default(),
            camera_offset: 0.0,
            use_emit_direction: false,
            life_span: 0.0,
            spawn_rate: Default::default(),
            spawn_burst: false,
            wave_delay: Default::default(),
            total_particles: Default::default(),
            max_concurrent_particles: 0,
            initial_velocity: Default::default(),
            velocity_stretch_multiplier: 0.0,
            particle_rotation_influence: ParticleRotationInfluence::None,
            particle_rotate_with_spawner: false,
            is_low_res: false,
            trail_spawner_position_multiplier: 0.0,
            trait_spawner_rotation_multiplier: 0.0,
            particle_collision: Default::default(),
            render_mode: FXRenderMode::BlendLinear,
            light_influence: 0.0,
            linear_filtering: false,
            particle_life_span: Default::default(),
            intersection_highlight: Default::default(),
            id: None,
            particle: None,
            uv_motion: None,
            attractors: vec![],
        });

        let packet = UpdateParticleSpawners {
            update_type: UpdateType::Init,
            particle_spawners: map,
            removed_particle_spawners: Vec::new()
        };

        let bytes = packet.encode().expect("Failed to encode");
        let packet = UpdateParticleSpawners::decode(&bytes).expect("Failed to decode");
    }
}