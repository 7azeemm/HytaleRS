use crate::protocol::packets::connect::Connect;
use crate::server::core::network::connection_manager::{ConnectionContext};
use crate::server::core::network::handlers::authentication_handler::AuthenticationPacketHandler;
use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_decoder::PacketDecoder;
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};

pub struct InitialPacketHandler {}

#[async_trait::async_trait]
impl PacketHandler for InitialPacketHandler {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> Result<HandlerAction, String> {
        match packet_id {
            0x00 => {
                let Some(packet) = PacketDecoder::decode::<Connect>(data) else {
                    return Ok(HandlerAction::Disconnect("Failed to decode packet!".to_string()));
                };

                Ok(HandlerAction::Transition(Box::new(AuthenticationPacketHandler {})))
            },
            _ => Err(format!("Unexpected packet 0x{:02X} in Handshake", packet_id)),
        }
    }
}
