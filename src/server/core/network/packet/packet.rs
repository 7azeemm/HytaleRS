use std::io::{Read, Write};
use super::packet_codec::CodecError;

/// Core packet trait with proper error handling
pub trait Packet: Send + Sync {
    /// Get this packet's ID
    fn packet_id(&self) -> u32;

    /// Get packet ID without instance (for routing/registration)
    fn default_id() -> u32;

    /// Encode packet to bytes
    fn encode(&self, writer: &mut dyn Write) -> std::io::Result<()>;

    /// Decode packet from bytes with error context
    fn decode(reader: &mut dyn Read) -> Result<Self, CodecError>
    where
        Self: Sized;
}