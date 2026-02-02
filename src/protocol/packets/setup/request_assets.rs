use std::sync::Arc;
use log::info;
use crate::protocol::packets::setup::asset::{Asset, ASSET_HASH_LEN, MAX_ASSET_NAME_LEN};
use crate::server::core::network::packet::packet::{Packet, PacketField};
use crate::server::core::network::packet::packet_decoder::{read_varint_at, PacketDecoder};
use crate::server::core::network::packet::packet_error::PacketError;

#[derive(Debug)]
pub struct RequestAssets {
    pub assets: Vec<Arc<Asset>>,
}

impl Packet for RequestAssets {
    fn packet_id() -> u32 {
        23
    }

    fn encode(&self, _writer: &mut Vec<u8>) -> Result<(), PacketError> {
        unimplemented!()
    }

    fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        let mut dec = PacketDecoder::new(buf);

        let null_bits = dec.read_u8("null_bits")?;

        let assets = if (null_bits & 1) != 0 {
            let (assets_count, pos_after_varint) = read_varint_at(buf, dec.pos, "assets_count")?;

            // Move decoder position past the count varint
            dec.pos = pos_after_varint;
            let mut assets_vec = Vec::with_capacity(assets_count);

            // Decode each asset sequentially
            for _ in 0..assets_count {
                let current_pos = dec.pos;
                let asset = Asset::decode(&mut dec, current_pos as i32)?;

                // Calculate how many bytes this asset consumed
                let bytes_consumed = compute_asset_bytes_consumed(buf, current_pos)?;

                // Advance position by the number of bytes consumed
                dec.pos = current_pos + bytes_consumed;
                assets_vec.push(Arc::new(asset));
            }

            assets_vec
        } else {
            Vec::new()
        };

        Ok(Self { assets })
    }
}

/// Calculate the total bytes consumed by an Asset in the buffer
fn compute_asset_bytes_consumed(buf: &[u8], pos: usize) -> Result<usize, PacketError> {
    if pos >= buf.len() {
        return Err(PacketError::DecodeEOF { field: "asset" });
    }

    let hash_end = pos + ASSET_HASH_LEN;
    if hash_end > buf.len() {
        return Err(PacketError::DecodeEOF { field: "asset_hash" });
    }

    // Read the name length varint at the position after the hash
    let (name_len, pos_after_varint) = read_varint_at(buf, hash_end, "asset_name_length")?;

    if name_len > MAX_ASSET_NAME_LEN {
        return Err(PacketError::EncodeStringTooLong {
            field: "asset_name",
            len: name_len,
            max: MAX_ASSET_NAME_LEN,
        });
    }

    let name_end = pos_after_varint + name_len;
    if name_end > buf.len() {
        return Err(PacketError::DecodeEOF { field: "asset_name" });
    }

    // Return total bytes consumed: from start pos to end of name
    Ok(name_end - pos)
}