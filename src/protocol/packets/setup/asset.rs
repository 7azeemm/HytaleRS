use std::io::Write;
use crate::server::core::network::packet::packet::PacketField;
use crate::server::core::network::packet::packet_error::PacketError;
use crate::server::core::network::packet::packet_decoder::PacketDecoder;
use crate::server::core::network::packet::packet_encoder::{write_varint, PacketEncoder};

const ASSET_HASH_LEN: usize = 64;
const MAX_ASSET_NAME_LEN: usize = 512;

#[derive(Debug, Clone)]
pub struct Asset {
    pub hash: String,
    pub name: String,
}

impl PacketField for Asset {
    fn encode(&self, writer: &mut dyn Write) -> Result<(), PacketError> {
        // Hash: 64 bytes fixed ASCII
        if self.hash.len() > ASSET_HASH_LEN {
            return Err(PacketError::EncodeStringTooLong {
                field: "asset_hash",
                len: self.hash.len(),
                max: ASSET_HASH_LEN,
            });
        }

        // Write hash bytes
        writer
            .write_all(self.hash.as_bytes())
            .map_err(|e| PacketError::Error {
                reason: "Failed to write asset hash",
                error: e.to_string(),
            })?;

        // Pad with zeros to exactly 64 bytes
        let padding = ASSET_HASH_LEN - self.hash.len();
        if padding > 0 {
            writer
                .write_all(&vec![0u8; padding])
                .map_err(|e| PacketError::Error {
                    reason: "Failed to write asset hash padding",
                    error: e.to_string(),
                })?;
        }

        // Name: varint LENGTH (in bytes) + UTF-8 bytes
        let name_bytes = self.name.as_bytes();

        if name_bytes.len() > MAX_ASSET_NAME_LEN {
            return Err(PacketError::EncodeStringTooLong {
                field: "asset_name",
                len: name_bytes.len(),
                max: MAX_ASSET_NAME_LEN,
            });
        }

        // Write varint byte length (NOT character count!)
        let mut len_buf = Vec::new();
        write_varint(&mut len_buf, name_bytes.len())?;
        writer.write_all(&len_buf).map_err(|e| PacketError::Error {
            reason: "Failed to write asset name length",
            error: e.to_string(),
        })?;

        // Write name bytes (UTF-8)
        writer.write_all(name_bytes).map_err(|e| PacketError::Error {
            reason: "Failed to write asset name",
            error: e.to_string(),
        })?;

        Ok(())
    }

    fn decode(_dec: &mut PacketDecoder, _offset: i32) -> Result<Self, PacketError> {
        unimplemented!("Asset is send-only")
    }
}