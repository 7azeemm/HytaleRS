use crate::handle_packet;
use crate::protocol::packets::connect::Connect;
use crate::server::core::hytale_server::HYTALE_SERVER;
use crate::server::core::network::connection_manager::{ConnectionContext};
use crate::server::core::network::handlers::authentication_handler::AuthenticationPacketHandler;
use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};
use crate::server::core::network::server_network_manager::PROTOCOL_CRC;

pub struct InitialPacketHandler {}

#[async_trait::async_trait]
impl PacketHandler for InitialPacketHandler {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> Result<HandlerAction, String> {
        match packet_id {
            0x00 => handle_packet!(Connect, data, handle_connect, cx),
            _ => Err(format!("Unexpected packet 0x{:02X} in Handshake", packet_id)),
        }
    }

    async fn register(&mut self, cx: &mut ConnectionContext) {
        cx.set_timeout(HYTALE_SERVER.config.read().await.timeouts.initial).await;
    }
}

async fn handle_connect(packet: Connect, cx: &mut ConnectionContext) -> Result<HandlerAction, String> {
    cx.clear_timeout().await;

    if packet.protocol_crc != PROTOCOL_CRC {
        return Ok(HandlerAction::Disconnect("incompatible protocols".into()))
    }

    println!("{:?}", packet);

    Ok(HandlerAction::Transition(Box::new(AuthenticationPacketHandler {})))
}
