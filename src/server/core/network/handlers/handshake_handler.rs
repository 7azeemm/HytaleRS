use std::time::Duration;
use log::{error, info};
use tokio::time::Instant;
use uuid::Uuid;
use crate::handle_packet;
use crate::protocol::packets::connection::auth_grant::AuthGrant;
use crate::protocol::packets::connection::auth_token::AuthToken;
use crate::protocol::packets::connection::connect::{ClientType, Connect, HostAddress};
use crate::protocol::packets::connection::server_auth_token::ServerAuthToken;
use crate::server::core::hytale_server::HYTALE_SERVER;
use crate::server::core::network::auth::jwt_validator::compute_certificate_fingerprint;
use crate::server::core::network::auth::server_auth_manager::ServerAuthManager;
use crate::server::core::network::connection_manager::{Connection, ConnectionContext};
use crate::server::core::network::handlers::setup_handler::SetupHandler;
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};
use crate::server::core::network::server_network_manager::SERVER_NETWORK_MANAGER;

pub struct HandshakePacketHandler {
    pub connect: Connect
}

#[async_trait::async_trait]
impl PacketHandler for HandshakePacketHandler {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> HandlerAction {
        match packet_id {
            12 => handle_packet!(self, AuthToken, data, handle_auth_token, cx),
            _ => HandlerAction::Error(format!("Unexpected packet 0x{:02X} in Handshake", packet_id)),
        }
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
        self.request_auth_grant(identity.to_owned(), cx).await;
    }
}

impl HandshakePacketHandler {
    async fn request_auth_grant(&self, identity_token: String, cx: &mut ConnectionContext) {
        cx.set_timeout(HYTALE_SERVER.config.read().await.timeouts.auth_grant).await;
        info!("Requesting auth grant for player: {}", &self.connect.username);
        let auth_manager = ServerAuthManager::get();

        let (session_token, server_identity_token) = {
            let game_session = auth_manager.game_session.lock().await;
            match game_session.as_ref().map(|s| (s.session_token.clone(), s.identity_token.clone())) {
                Some(tokens) => tokens,
                None => {
                    error!("Server not authenticated - cannot request auth grant");
                    cx.disconnect("Server authentication unavailable - please try again later").await;
                    return;
                }
            }
        };

        let Some(auth_grant) = auth_manager.session_service.request_auth_grant(&identity_token, &session_token).await else {
            cx.disconnect("Failed to obtain authorization grant from session service").await;
            return;
        };

        cx.send(AuthGrant { auth_grant, server_identity_token }).await;
        cx.set_timeout(HYTALE_SERVER.config.read().await.timeouts.auth_token).await;
    }

    async fn handle_auth_token(&self, packet: AuthToken, cx: &mut ConnectionContext) -> HandlerAction {
        let (Some(access_token), Some(server_auth_grant)) = (packet.access_token, packet.server_auth_grant) else {
            return HandlerAction::Disconnect("Invalid access token or auth grant".into());
        };

        info!("Received AuthToken from {}, validating JWT...", &self.connect.username);

        let claims = match ServerAuthManager::get().jwt_validator.validate_token(&access_token, &cx.client_cert).await {
            Ok(claims) => claims,
            Err(err) => {
                error!("JWT Validation failed for {}: {}", &self.connect.username, err);
                return HandlerAction::Disconnect("Invalid access token".into());
            }
        };

        if claims.username.as_ref() != Some(&self.connect.username) {
            error!("JWT username mismatch for {}", &self.connect.username);
            return HandlerAction::Disconnect("Invalid token claims: username mismatch".into())
        }

        cx.set_timeout(HYTALE_SERVER.config.read().await.timeouts.auth_server_exchange).await;
        self.exchange_server_auth_grant(&server_auth_grant, cx).await
    }

    async fn exchange_server_auth_grant(&self, auth_grant: &str, cx: &mut ConnectionContext) -> HandlerAction {
        info!("Exchanging auth grant for access token...");
        let auth_manager = ServerAuthManager::get();

        let server_cert = &SERVER_NETWORK_MANAGER.get().unwrap().server_certificate;
        let Some(server_cert_fingerprint) = compute_certificate_fingerprint(server_cert) else {
            error!("Server not authenticated - server certificate fingerprint not available");
            return HandlerAction::Disconnect("Server authentication unavailable - please try again later".into())
        };

        let session_token = {
            let game_session = auth_manager.game_session.lock().await;
            match game_session.as_ref().map(|s| s.session_token.clone()) {
                Some(token) => token,
                None => {
                    error!("Server not authenticated - server session token not available");
                    return HandlerAction::Disconnect("Server authentication unavailable - please try again later".into());
                }
            }
        };

        let Some(access_token) = auth_manager.session_service.exchange_auth_grant_for_token(auth_grant, &server_cert_fingerprint, &session_token).await else {
            return HandlerAction::Disconnect("Server authentication unavailable - please try again later".into());
        };

        info!("Sending server auth token to {}", &self.connect.username);
        cx.send(ServerAuthToken { access_token, password_challenge: Vec::new() }).await;
        self.complete_auth(cx).await
    }

    pub async fn complete_auth(&self, cx: &mut ConnectionContext) -> HandlerAction {
        cx.clear_timeout().await;
        info!("Mutual authentication complete for {}", self.connect.username);
        info!("Connection complete for {}, transitioning to setup...", self.connect.username);

        HandlerAction::Transition(Box::new(SetupHandler {
            player_auth: PlayerAuthentication {
                uuid: self.connect.uuid,
                username: self.connect.username.clone(),
                language: self.connect.language.clone(),
                referral_data: self.connect.referral_data.clone(),
                referral_source: self.connect.referral_source.clone()
            }
        }))
    }
}

pub struct PlayerAuthentication {
    pub uuid: Uuid,
    pub username: String,
    pub language: String,
    pub referral_data: Option<Vec<u8>>,
    pub referral_source: Option<HostAddress>,
}