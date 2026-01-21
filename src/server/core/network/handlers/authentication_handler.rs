use log::info;
use crate::server::core::network::connection_manager::{Connection, ConnectionContext};
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};

pub struct AuthenticationPacketHandler {}

#[async_trait::async_trait]
impl PacketHandler for AuthenticationPacketHandler {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> Result<HandlerAction, String> {
        info!("Packet Received in AuthenticationHandler: {packet_id}");
        Err("Returned".to_owned())
    }
}