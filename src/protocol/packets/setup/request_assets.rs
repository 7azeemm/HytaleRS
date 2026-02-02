use std::sync::Arc;
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

    fn encode(&self, writer: &mut Vec<u8>) -> Result<(), PacketError> {
        unimplemented!()
    }

    fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        println!("RequestAssets buffer len: {}, first 20 bytes: {:?}", buf.len(), &buf[..20.min(buf.len())]);

        let mut dec = PacketDecoder::new(buf);

        let null_bits = dec.read_u8("null_bits")?;
        println!("null_bits: 0x{:02x}, dec.pos after: {}", null_bits, dec.pos);

        let assets = if (null_bits & 1) != 0 {
            let (assets_count, pos_after_varint) = read_varint_at(buf, dec.pos, "assets_count")?;
            println!("assets_count: {}, pos_after_varint: {}", assets_count, pos_after_varint);


            if assets_count > 4_096_000 {
                return Err(PacketError::Error {
                    reason: "Assets array too long",
                    error: format!("expected max 4096000, got {}", assets_count),
                });
            }

            dec.pos = pos_after_varint;  // ✅ Skip past the count varint
            let mut assets_vec = Vec::with_capacity(assets_count);

            for _ in 0..assets_count {
                let current_pos = dec.pos;  // ✅ Save before decode
                let asset = Asset::decode(&mut dec, current_pos as i32)?;
                let bytes_consumed = compute_asset_bytes_consumed(buf, current_pos)?;  // ✅ Use saved position
                dec.pos = current_pos + bytes_consumed;  // ✅ Advance by consumed bytes
                assets_vec.push(Arc::new(asset));
            }

            assets_vec
        } else {
            Vec::new()
        };

        Ok(Self { assets })
    }
}

fn varint_size(mut value: usize) -> usize {
    let mut size = 1;
    while value >= 0x80 {
        value >>= 7;
        size += 1;
    }
    size
}

fn compute_varint_size(value: usize) -> usize {
    if value < 128 { 1 } else { ((value.ilog2() / 7) + 1) as usize }
}

fn compute_asset_bytes_consumed(buf: &[u8], pos: usize) -> Result<usize, PacketError> {
    let hash_end = pos + ASSET_HASH_LEN;

    if hash_end >= buf.len() {
        return Err(PacketError::DecodeEOF { field: "asset_name_length" });
    }

    // Read varint - returns (name_len, pos_after_varint)
    let (name_len, pos_after_varint) = read_varint_at(buf, hash_end, "asset_name_length")?;

    if name_len > MAX_ASSET_NAME_LEN {
        return Err(PacketError::EncodeStringTooLong {
            field: "asset_name",
            len: name_len,
            max: MAX_ASSET_NAME_LEN,
        });
    }

    let name_end = pos_after_varint + name_len;

    // Total bytes consumed: from start position to end of name
    Ok(name_end - pos)
}