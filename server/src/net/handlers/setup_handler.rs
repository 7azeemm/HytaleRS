use crate::assets::asset_registry::STORE_REGISTRY;
use crate::assets::common::common_asset_registry::COMMON_ASSET_REGISTRY;
use crate::config::WORLD_HEIGHT;
use crate::handle_packet;
use crate::net::connection_manager::ConnectionContext;
use crate::net::handlers::handshake_handler::PlayerAuthentication;
use crate::net::handlers::packet_handler::{HandlerAction, PacketHandler};
use crate::server::HytaleServer;
use log::info;
use protocol::io::codecs::VarList;
use protocol::packets::setup::{
    Asset, RequestAssets, ServerInfo, WorldLoadFinished, WorldLoadProgress, WorldSettings,
};
use std::sync::Arc;

pub struct SetupHandler {
    pub player_auth: PlayerAuthentication,
}

#[async_trait::async_trait]
impl PacketHandler for SetupHandler {
    async fn handle(
        &mut self,
        packet_id: u32,
        data: &[u8],
        cx: &mut ConnectionContext,
    ) -> HandlerAction {
        match packet_id {
            23 => handle_packet!(self, RequestAssets, data, handle_request_assets, cx),
            _ => HandlerAction::Error(format!("Unexpected packet {} in setup", packet_id)),
        }
    }

    async fn register(&mut self, cx: &mut ConnectionContext) {
        let server_config = HytaleServer::get().config.read().await;
        let setup_world_timeout = server_config.timeouts.setup_world_settings;
        let server_name = server_config.server_name.clone();
        let motd = server_config.motd.clone();
        let max_players = server_config.max_players as i32;
        drop(server_config);

        cx.set_timeout(setup_world_timeout).await;

        let required_assets: VarList<Arc<Asset>, _> = COMMON_ASSET_REGISTRY.get_assets().into();
        info!("Sending {} common assets to client", required_assets.len());

        cx.send(WorldSettings {
            world_height: WORLD_HEIGHT,
            required_assets,
        })
        .await;

        cx.send(ServerInfo {
            max_players,
            server_name: Some(server_name),
            motd: Some(motd),
        })
        .await;
    }
}

impl SetupHandler {
    async fn handle_request_assets(
        &self,
        packet: RequestAssets,
        cx: &mut ConnectionContext,
    ) -> HandlerAction {
        info!("Client requested {} assets", packet.assets.len());

        STORE_REGISTRY.send_assets(cx).await;

        cx.send(WorldLoadProgress {
            status: "Loading World".to_owned(),
            percent_complete: 0,
            percent_complete_subitem: 0,
        })
        .await;
        cx.send(WorldLoadFinished {}).await;

        HandlerAction::Continue
    }
}
