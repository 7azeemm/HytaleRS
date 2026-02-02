use std::io::Write;
use crate::server::core::network::packet::packet::PacketField;
use crate::server::core::network::packet::packet_error::PacketError;
use crate::server::core::network::packet::packet_decoder::{read_varint_at, PacketDecoder};
use crate::server::core::network::packet::packet_encoder::{write_varint, PacketEncoder};

pub const ASSET_HASH_LEN: usize = 64;
pub const MAX_ASSET_NAME_LEN: usize = 512;

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

    fn decode(dec: &mut PacketDecoder, offset: i32) -> Result<Self, PacketError> {
        if offset < 0 {
            return Err(PacketError::DecodeNegativeOffset { field: "asset", offset });
        }

        let offset = offset as usize;
        let buf = dec.buf;

        // Read fixed 64-byte hash
        if offset + ASSET_HASH_LEN > buf.len() {
            return Err(PacketError::DecodeEOF { field: "asset_hash" });
        }

        let hash_bytes = &buf[offset..offset + ASSET_HASH_LEN];
        let hash = String::from_utf8(hash_bytes.to_vec())
            .map_err(|_| PacketError::DecodeInvalidUtf8 { field: "asset_hash" })?
            .trim_end_matches('\0')
            .to_string();

        // Read varint-prefixed name after the hash
        let name_pos = offset + ASSET_HASH_LEN;

        if name_pos >= buf.len() {
            return Err(PacketError::DecodeEOF { field: "asset_name_length" });
        }

        // Read varint length - returns (name_len, pos_after_varint)
        let (name_len, pos_after_varint) = read_varint_at(buf, name_pos, "asset_name_length")?;

        if name_len > MAX_ASSET_NAME_LEN {
            return Err(PacketError::EncodeStringTooLong {
                field: "asset_name",
                len: name_len,
                max: MAX_ASSET_NAME_LEN,
            });
        }

        // Read the actual name string
        let name_start = pos_after_varint;  // ✅ Use the position AFTER varint
        let name_end = name_start + name_len;

        if name_end > buf.len() {
            return Err(PacketError::DecodeEOF { field: "asset_name" });
        }

        let name = String::from_utf8(buf[name_start..name_end].to_vec())
            .map_err(|_| PacketError::DecodeInvalidUtf8 { field: "asset_name" })?;

        Ok(Self { hash, name })
    }
}