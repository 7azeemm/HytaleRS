use std::sync::Arc;
use log::info;
use crate::assets::common::common_asset_registry::COMMON_ASSET_REGISTRY;
use crate::handle_packet;
use crate::protocol::packets::connection::auth_token::AuthToken;
use crate::protocol::packets::setup::asset::Asset;
use crate::protocol::packets::setup::request_assets::RequestAssets;
use crate::protocol::packets::setup::server_info::ServerInfo;
use crate::protocol::packets::setup::world_load_finished::WorldLoadFinished;
use crate::protocol::packets::setup::world_load_progress::WorldLoadProgress;
use crate::protocol::packets::setup::world_settings::WorldSettings;
use crate::server::core::hytale_server::HYTALE_SERVER;
use crate::server::core::hytale_server_config::WORLD_HEIGHT;
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
            23 => handle_packet!(self, RequestAssets, data, handle_request_assets, cx),
            _ => HandlerAction::Error(format!("Unexpected packet {} in setup", packet_id)),
        }
    }

    async fn register(&mut self, cx: &mut ConnectionContext) {
        let server_config = HYTALE_SERVER.config.read().await;
        let setup_world_timeout = server_config.timeouts.setup_world_settings;
        let server_name = server_config.server_name.clone();
        let motd = server_config.motd.clone();
        let max_players = server_config.max_players as i32;
        drop(server_config);

        cx.set_timeout(setup_world_timeout).await;

        let required_assets = COMMON_ASSET_REGISTRY.get_assets();
        info!("Sending {} common assets to client", required_assets.len());

        cx.send(WorldSettings { world_height: WORLD_HEIGHT, required_assets }).await;
        cx.send(ServerInfo { server_name, motd, max_players }).await;
    }
}

impl SetupHandler {
    async fn handle_request_assets(&self, packet: RequestAssets, cx: &mut ConnectionContext) -> HandlerAction {
        info!("Client requested {} assets", packet.assets.len());

        cx.send(WorldLoadProgress {
            status: "Loading World".to_owned(),
            percent_complete: 0,
            percent_complete_subitem: 0
        }).await;
        cx.send(WorldLoadFinished {}).await;

        HandlerAction::Continue
    }
}