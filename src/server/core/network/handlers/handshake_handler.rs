use std::time::Duration;
use log::{error, info};
use tokio::time::Instant;
use crate::protocol::packets::connect::{ClientType, Connect};
use crate::server::core::hytale_server::HYTALE_SERVER;
use crate::server::core::network::auth::server_auth_manager::ServerAuthManager;
use crate::server::core::network::connection_manager::{Connection, ConnectionContext};
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};

pub struct HandshakePacketHandler {
    pub connect: Connect
}

#[async_trait::async_trait]
impl PacketHandler for HandshakePacketHandler {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> HandlerAction {
        info!("Packet Received in AuthenticationHandler: {packet_id}");

        HandlerAction::Continue
    }

    async fn register(&mut self, cx: &mut ConnectionContext) {
        cx.set_timeout(HYTALE_SERVER.config.read().await.timeouts.auth).await;
        let start_time = Instant::now();

        let identity = match &self.connect.identity_token {
            Some(identity) => identity,
            None => {
                error!("Identity token is unavailable");
                cx.disconnect("Identity token is unavailable").await;
                return;
            }
        };

        let claims = match ServerAuthManager::get().jwt_validator.validate_identity_token(identity).await {
            Ok(claims) => claims,
            Err(err) => {
                error!("Failed to validate identity token for {}: {}", self.connect.username, err);
                cx.disconnect("Invalid or expired identity token").await;
                return
            }
        };

        if self.connect.uuid.to_string() != claims.sub {
            error!("Identity token UUID mismatch for {}", self.connect.username);
            cx.disconnect("Invalid identity token: UUID mismatch").await;
            return
        }

        let required_scope = match self.connect.client_type {
            ClientType::Game => "hytale:client",
            ClientType::Editor => "hytale:editor"
        };

        if claims.scope.is_none() || claims.scope.unwrap() != required_scope {
            error!("Identity token missing required scope for {}", self.connect.username);
            cx.disconnect("Invalid identity token: missing required scope").await;
            return
        }

        info!("Successfully validated identity token for user {} in {:?}", self.connect.username, start_time.elapsed());
        self.request_auth_grant(cx).await;
    }
}

impl HandshakePacketHandler {
    async fn request_auth_grant(&self, cx: &mut ConnectionContext) {
        cx.set_timeout(HYTALE_SERVER.config.read().await.timeouts.auth_grant).await;
    }
}