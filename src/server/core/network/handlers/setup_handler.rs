use crate::server::core::hytale_server::HYTALE_SERVER;
use crate::server::core::network::connection_manager::ConnectionContext;
use crate::server::core::network::handlers::handshake_handler::PlayerAuthentication;
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};

pub struct SetupHandler {
    pub player_auth: PlayerAuthentication
}

#[async_trait::async_trait]
impl PacketHandler for SetupHandler {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> HandlerAction {
        match packet_id {
            // 12 => handle_packet!(self, AuthToken, data, handle_auth_token, cx),
            _ => HandlerAction::Error(format!("Unexpected packet 0x{:02X} in setup", packet_id)),
        }
    }

    async fn register(&mut self, cx: &mut ConnectionContext) {
        cx.set_timeout(HYTALE_SERVER.config.read().await.timeouts.setup_world_settings).await;
        
    }
}