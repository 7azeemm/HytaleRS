use std::io::Cursor;
use std::time::Instant;
use log::{error, info};
use quinn::{ReadError, ReadExactError, RecvStream};
use tokio::io::AsyncReadExt;
use protocol::io::packet::{get_packet_info, Packet};
use protocol::io::errors::PacketResult;

/// write framed packet to bytes
pub fn write_packet<P: Packet>(packet: &P) -> PacketResult<Vec<u8>> {
    let start_time = Instant::now();
    let packet_id = P::ID;
    let Some(packet_info) = get_packet_info(packet_id) else {
        return Err(format!("Packet ID {} not registered", packet_id).into());
    };

    // Encode payload
    let mut payload = Packet::encode(packet)
        .map_err(|e| format!("Failed to encode packet {}: {}", P::name(), e))?;

    // Compress payload if needed and not empty
    if packet_info.is_compressed && !payload.is_empty() {
        payload = zstd::bulk::compress(&payload, 3)
            .map_err(|e| format!("Failed to compress packet {}: {}", P::name(), e))?;
    }

    // Prepare final packet buffer: [length][packet_id][payload]
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&packet_id.to_le_bytes());
    out.extend_from_slice(&payload);

    info!("Encoded Packet {} in {:?}: {} bytes", P::name(), start_time.elapsed(), payload.len());

    Ok(out)
}

/// Read framed packet from stream
pub async fn read_packet(recv: &mut RecvStream) -> PacketResult<(u32, Vec<u8>)> {
    let payload_len = recv.read_i32_le().await? as u32;
    let packet_id = recv.read_i32_le().await? as u32;
    let Some(packet_info) = get_packet_info(packet_id) else {
        return Err(format!("Packet ID {} not registered", packet_id).into());
    };

    if payload_len > packet_info.max_size {
        return Err(format!("Packet {} size {} exceeds max {}", packet_info.name(), payload_len, packet_info.max_size).into())
    }

    if payload_len == 0 {
        return Ok((packet_id, Vec::new()))
    }

    let mut payload = vec![0u8; payload_len as usize];
    recv.read_exact(&mut payload).await
        .map_err(|e| format!("Failed to read packet {}: {}", packet_info.name(), e))?;

    if packet_info.is_compressed {
        let mut decompressed = Vec::new();
        let mut reader = Cursor::new(&payload);

        zstd::stream::copy_decode(&mut reader, &mut decompressed)
            .map_err(|e| format!("Failed to decompress packet {}: {}", packet_info.name(), e))?;

        payload = decompressed;
    }

    Ok((packet_id, payload))
}

pub fn decode<P: Packet>(data: &[u8]) -> Option<P> {
    let start_time = Instant::now();
    let packet: P = match Packet::decode(data) {
        Ok(p) => p,
        Err(err) => {
            error!("Failed to decode packet {}: {}", P::name(), err);
            return None
        }
    };

    info!("Decoded Packet {} in {:?}", P::name(), start_time.elapsed());
    Some(packet)
}