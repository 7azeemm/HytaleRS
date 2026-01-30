use crate::protocol::packets::setup::asset::Asset;
use crate::protocol::packets::setup::server_info::ServerInfo;
use crate::protocol::packets::setup::world_settings::WorldSettings;
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

        let mut assets = Vec::new();
        assets.push(Asset {
            hash: "845230ce3a3636aa30e426bbd8224987254f5556f8bb7a79fe60339ea5d1c639".to_owned(),
            name: "BlockTextures/Bone_Side.png".to_owned()
        });

        cx.send(WorldSettings {
            world_height: 320,
            required_assets: assets
        }).await;
        // cx.send(ServerInfo {
        //     server_name: "Rust".to_string(),
        //     motd: "idk".to_string(),
        //     max_players: 10
        // }).await;
    }
}