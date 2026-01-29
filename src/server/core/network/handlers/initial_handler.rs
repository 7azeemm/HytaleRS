use std::sync::atomic::Ordering;
use log::info;
use crate::handle_packet;
use crate::protocol::packets::connection::connect::{ClientType, Connect};
use crate::server::core::hytale_server::{BOOTED, HYTALE_SERVER, SHUTTING_DOWN};
use crate::server::core::network::connection_manager::{ConnectionContext};
use crate::server::core::network::handlers::handshake_handler::HandshakePacketHandler;
use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};
use crate::server::core::network::server_network_manager::PROTOCOL_CRC;
use crate::server::core::options::Options;

pub struct InitialPacketHandler {}

#[async_trait::async_trait]
impl PacketHandler for InitialPacketHandler {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> HandlerAction {
        cx.clear_timeout().await;
        match packet_id {
            0x00 => handle_packet!(self, Connect, data, handle_connect, cx),
            _ => HandlerAction::Error(format!("Unexpected packet 0x{:02X} in Handshake", packet_id)),
        }
    }

    async fn register(&mut self, cx: &mut ConnectionContext) {
        cx.set_timeout(HYTALE_SERVER.config.read().await.timeouts.initial).await;
    }
}

impl InitialPacketHandler {
    async fn handle_connect(&self, packet: Connect, cx: &mut ConnectionContext) -> HandlerAction {
        if packet.protocol_crc != PROTOCOL_CRC {
            return HandlerAction::Disconnect("Incompatible protocols".into())
        }

        if !BOOTED.load(Ordering::Relaxed) {
            return HandlerAction::Disconnect("Server is booting up!".into())
        }

        if SHUTTING_DOWN.load(Ordering::Relaxed) {
            return HandlerAction::Disconnect("Server is shutting down!".into())
        }

        if matches!(packet.client_type, ClientType::Game) {
            // TODO: check if universe reached max players limit
            return HandlerAction::Transition(Box::new(
                HandshakePacketHandler { connect: packet }
            ))
        }

        // TODO: Editor Client

        HandlerAction::Disconnect("Editor Client is not supported yet.".into())
    }
}