use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum_macros::Display;
use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_error::PacketError;
use crate::server::core::network::packet::packet_decoder::PacketDecoder;
use crate::server::core::network::packet::packet_encoder::PacketEncoder;

#[derive(Debug)]
pub struct Disconnect {
    pub reason: Option<String>,
    pub cause: DisconnectCause
}

#[derive(Debug, IntoPrimitive, TryFromPrimitive, Display, Clone, Copy)]
#[repr(u8)]
pub enum DisconnectCause {
    Disconnect,
    Crash
}

impl Packet for Disconnect {
    fn packet_id() -> u32 {
        1
    }

    fn encode(&self, writer: &mut Vec<u8>) -> Result<(), PacketError> {
        let mut enc = PacketEncoder::new(writer);

        let nulls = if self.reason.is_some() { 1 << 0 } else { 0 };
        enc.write_null_bits(nulls);
        enc.write_u8(self.cause as u8);

        let mut offsets = enc.reserve_offsets::<1>()?;
        offsets.write_opt_string(self.reason.as_deref())?;
        offsets.finish()?;
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        let mut dec = PacketDecoder::new(buf);
        let nulls = dec.read_null_bits()?;
        let cause = DisconnectCause::try_from(dec.read_u8("cause")?)?;
        let offsets = dec.read_offsets::<1>()?;
        let reason = dec.read_opt_string(nulls, 1, offsets[0], "reason")?;
        Ok(Self { reason, cause })
    }
}