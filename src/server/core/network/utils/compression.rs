use crate::server::core::network::packet::packet_error::PacketError;

/// Compress data using Zstd
pub fn compress(data: &[u8]) -> Result<Vec<u8>, PacketError> {
    zstd::encode_all(data, 0)
        .map_err(|e| PacketError::Error {
            reason: "Zstd compression failed",
            error: e.to_string(),
        })
}

/// Decompress data using Zstd
pub fn decompress(data: &[u8], max_size: usize) -> Result<Vec<u8>, PacketError> {
    zstd::decode_all(data)
        .map_err(|e| PacketError::Error {
            reason: "Zstd decompression failed",
            error: e.to_string(),
        })
        .and_then(|decompressed| {
            if decompressed.len() > max_size {
                Err(PacketError::Error {
                    reason: "Decompressed data exceeds maximum size",
                    error: format!(
                        "decompressed {} bytes, max {}",
                        decompressed.len(),
                        max_size
                    ),
                })
            } else {
                Ok(decompressed)
            }
        })
}