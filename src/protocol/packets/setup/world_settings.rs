use crate::server::core::network::packet::packet::{Packet, PacketField};
use crate::server::core::network::packet::packet_error::PacketError;
use crate::server::core::network::packet::packet_encoder::PacketEncoder;
use crate::protocol::packets::setup::asset::Asset;

#[derive(Debug)]
pub struct WorldSettings {
    pub world_height: i32,
    pub required_assets: Vec<Asset>,
}

impl Packet for WorldSettings {
    fn packet_id() -> u32 {
        20
    }

    fn encode(&self, writer: &mut Vec<u8>) -> Result<(), PacketError> {
        let mut enc = PacketEncoder::new(writer);

        // Null bits: bit 0 = required_assets present
        let null_bits = if self.required_assets.is_empty() { 0u8 } else { 1u8 };
        enc.write_null_bits(null_bits);

        // World height
        enc.write_i32(self.world_height);

        // Required assets
        if !self.required_assets.is_empty() {
            enc.write_var_u32(self.required_assets.len() as u32);
            for asset in &self.required_assets {
                asset.encode(writer)?;
            }
        }

        Ok(())
    }

    fn decode(_buf: &[u8]) -> Result<Self, PacketError> {
        unimplemented!("WorldSettings is send-only")
    }
}