use log::info;
use crate::server::core::network::packet::packet::Packet;

pub mod connection;
pub mod setup;

pub fn test_packet<P: Packet>(packet: &P) -> P {
    let mut buf = Vec::new();
    match packet.encode(&mut buf) {
        Ok(_) => println!("✓ Encoded Packet {} ({} bytes)", P::packet_id(), buf.len()),
        Err(e) => panic!("Failed to encode packet {}: {:?}", P::packet_id(), e)
    }

    match P::decode(&buf) {
        Ok(decoded) => {
            info!("✓ Decoded Packet {}", P::packet_id());
            decoded
        }
        Err(e) => panic!("Failed to decode packet {}: {:?}", P::packet_id(), e)
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::packets::connection::disconnect::{Disconnect, DisconnectCause};
    use crate::protocol::packets::test_packet;

    #[test]
    fn test_disconnect() {
        let packet = Disconnect {
            reason: Some("test".to_string()),
            cause: DisconnectCause::Crash,
        };

        let decoded = test_packet(&packet);

        assert_eq!(packet.reason, decoded.reason);
        assert_eq!(packet.cause as u8, decoded.cause as u8);
    }
}