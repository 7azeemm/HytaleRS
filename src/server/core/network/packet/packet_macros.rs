#[macro_export]
macro_rules! handle_packet {
    ($packet_type:ty, $data:expr, $handler:expr, $cx:expr) => {{
        match $crate::server::core::network::packet::packet_decoder::PacketDecoder::decode::<$packet_type>($data) {
            Some(packet) => $handler(packet, $cx).await,
            None => Err("Failed to decode packet".to_string()),
        }
    }};
}