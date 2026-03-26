use std::fmt::Debug;
use macros::packet_field;
use crate::io::codecs::PacketCodec;
use crate::io::decoder::Decoder;
use crate::io::encoder::Encoder;
use crate::io::errors::{PacketError, PacketResult};

#[derive(Debug, Clone)]
pub struct ParamValue {
    pub packet: Box<dyn ParamKind>
}

impl Clone for Box<dyn ParamKind> {
    fn clone(&self) -> Box<dyn ParamKind> {
        self.clone_box()
    }
}

pub trait ParamKind: Debug + Send + Sync {
    fn id(&self) -> usize;
    fn encode(&self, enc: &mut Encoder) -> PacketResult<()>;
    fn clone_box(&self) -> Box<dyn ParamKind>;
}

impl PacketCodec for ParamValue {
    const SIZE: Option<usize> = None;

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        enc.write_varint(self.packet.id())?;
        self.packet.encode(enc)
    }

    fn decode(dec: &mut Decoder) -> PacketResult<Self> {
        let id = dec.read_varint()?;
        let packet: Box<dyn ParamKind> = match id {
            0 => Box::new(StringParamValue::decode(dec)?),
            1 => Box::new(BoolParamValue::decode(dec)?),
            2 => Box::new(DoubleParamValue::decode(dec)?),
            3 => Box::new(IntParamValue::decode(dec)?),
            4 => Box::new(LongParamValue::decode(dec)?),
            _ => return Err(PacketError::DecodeError(format!("Unknown Interaction Id: {id}")))
        };

        Ok(ParamValue { packet })
    }
}

#[packet_field]
pub struct StringParamValue {
    pub value: Option<String>
}

impl ParamKind for StringParamValue {
    fn id(&self) -> usize { 0 }

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        PacketCodec::encode(self, enc)
    }

    fn clone_box(&self) -> Box<dyn ParamKind> {
        Box::new(self.clone())
    }
}

#[packet_field]
pub struct BoolParamValue {
    pub value: bool
}

impl ParamKind for BoolParamValue {
    fn id(&self) -> usize { 1 }

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        PacketCodec::encode(self, enc)
    }

    fn clone_box(&self) -> Box<dyn ParamKind> {
        Box::new(self.clone())
    }
}

#[packet_field]
pub struct DoubleParamValue {
    pub value: f64
}

impl ParamKind for DoubleParamValue {
    fn id(&self) -> usize { 2 }

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        PacketCodec::encode(self, enc)
    }

    fn clone_box(&self) -> Box<dyn ParamKind> {
        Box::new(self.clone())
    }
}

#[packet_field]
pub struct IntParamValue {
    pub value: i32
}

impl ParamKind for IntParamValue {
    fn id(&self) -> usize { 3 }

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        PacketCodec::encode(self, enc)
    }

    fn clone_box(&self) -> Box<dyn ParamKind> {
        Box::new(self.clone())
    }
}

#[packet_field]
pub struct LongParamValue {
    pub value: i64
}

impl ParamKind for LongParamValue {
    fn id(&self) -> usize { 4 }

    fn encode(&self, enc: &mut Encoder) -> PacketResult<()> {
        PacketCodec::encode(self, enc)
    }

    fn clone_box(&self) -> Box<dyn ParamKind> {
        Box::new(self.clone())
    }
}