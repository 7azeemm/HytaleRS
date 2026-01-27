use crate::server::core::network::packet::packet::Packet;

pub mod connect;
pub mod disconnect;

pub fn test_packet<P: Packet>(packet: &P) -> P {
    let mut buf = Vec::new();
    match packet.encode(&mut buf) {
        Ok(_) => println!("✓ Encoded 0x{:02X} ({} bytes)", P::packet_id(), buf.len()),
        Err(e) => panic!("Failed to encode 0x{:02X}: {:?}", P::packet_id(), e)
    }

    match P::decode(&buf) {
        Ok(decoded) => {
            println!("✓ Decoded 0x{:02X}", P::packet_id());
            decoded
        }
        Err(e) => panic!("Failed to decode 0x{:02X}: {:?}", P::packet_id(), e)
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::packets::disconnect::{Disconnect, DisconnectCause};
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