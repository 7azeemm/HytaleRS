use std::collections::HashMap;
use std::fmt::Debug;
use macros::{packet, packet_enum, packet_field};
use crate::io::codecs::{FixedOption, PacketCodec};
use crate::io::decoder::Decoder;
use crate::io::encoder::Encoder;
use crate::io::errors::{PacketError, PacketResult};
use crate::io::packet::PacketLayout;
use crate::objects::objects::{Direction, Vec3f};
use crate::packets::assets::entity_effect::MovementEffectsPacket;
use crate::packets::assets::interactions::interaction_type::InteractionType;
use crate::packets::assets::interactions::apply_effect_interaction::ApplyEffectInteraction;
use crate::packets::assets::interactions::simple_block_interaction::SimpleBlockInteraction;
use crate::packets::assets::item::ModelTrail;
use crate::packets::assets::model_particle::ModelParticlePacket;
use crate::packets::assets::update_type::UpdateType;

type DecoderFn = fn(&mut Decoder) -> PacketResult<Box<dyn InteractionKind>>;

static DECODERS: &[Option<DecoderFn>] = &[
    Some(|dec| Ok(Box::new(SimpleBlockInteraction::decode(dec)?))),
    Some(|dec| Ok(Box::new(ApplyEffectInteraction::decode(dec)?))),
];

#[packet(id = 66, max_size = 0x64000000, compressed)]
pub struct UpdateInteractions {
    pub update_type: UpdateType,
    pub max_id: i32,
    pub interactions: HashMap<i32, InteractionPacket>
}

#[derive(Debug, Clone)]
pub struct InteractionPacket {
    pub packet: Box<dyn InteractionKind>
}

impl Clone for Box<dyn InteractionKind> {
    fn clone(&self) -> Box<dyn InteractionKind> {
        self.clone_box()
    }
}

pub trait InteractionKind: Debug + Send + Sync {
    fn id(&self) -> usize;
    fn encode(&self, enc: &mut Encoder) -> PacketResult<()>;
    fn clone_box(&self) -> Box<dyn InteractionKind>;
}

impl PacketCodec for InteractionPacket {
    const SIZE: Option<usize> = None;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_varint(self.packet.id())?;
        self.packet.encode(enc)
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let id = dec.read_varint()?;
        let decoder = DECODERS
            .get(id)
            .and_then(|d| d.as_ref())
            .ok_or(PacketError::DecodeError(format!("Unknown Interaction Id: {id}")))?;

        let packet = decoder(dec)?;
        Ok(InteractionPacket { packet })
    }
}

#[packet_enum]
pub enum InteractionTarget {
    User,
    Owner,
    Target
}

#[packet_field]
pub struct InteractionRules {
    pub blocked_by_bypass_index: i32,
    pub blocking_bypass_index: i32,
    pub interrupted_by_bypass_index: i32,
    pub interrupting_bypass_index: i32,
    pub blocked_by: Vec<InteractionType>,
    pub blocking: Vec<InteractionType>,
    pub interrupted_by: Vec<InteractionType>,
    pub interrupting: Vec<InteractionType>,
}

#[packet_field]
pub struct InteractionSettings {
    pub allow_skip_on_click: bool
}

#[packet_field]
pub struct InteractionEffects {
    pub world_sound_event_index: i32,
    pub local_sound_event_index: i32,
    pub wait_for_animation_to_finish: bool,
    pub clear_animation_on_finish: bool,
    pub clear_sound_event_on_finish: bool,
    pub camera_shake: FixedOption<CameraShakeEffect>,
    pub movement_effects: FixedOption<MovementEffectsPacket>,
    pub start_delay: f32,
    pub particles: Vec<ModelParticlePacket>,
    pub first_person_particles: Vec<ModelParticlePacket>,
    pub trails: Vec<ModelTrail>,
    pub item_player_animation_id: Option<String>,
    pub item_animation_id: Option<String>,
}

#[packet_field]
pub struct CameraShakeEffect {
    pub camera_shake_id: i32,
    pub intensity: f32,
    pub mode: AccumulationMode
}

#[packet_field]
pub struct InteractionCameraSettings {
    pub first_person: Vec<InteractionCamera>,
    pub third_person: Vec<InteractionCamera>,
}

#[packet_field]
pub struct InteractionCamera {
    pub time: f32,
    pub position: FixedOption<Vec3f>,
    pub rotation: FixedOption<Direction>
}

#[packet_enum]
pub enum AccumulationMode {
    Set,
    Sum,
    Average
}

#[packet_enum]
#[derive(Eq, PartialEq, Hash)]
pub enum GameMode {
    Adventure,
    Creative
}

#[packet_enum]
pub enum WaitForDataFrom {
    Client,
    Server,
    None
}