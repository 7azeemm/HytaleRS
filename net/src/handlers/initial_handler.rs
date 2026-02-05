use protocol::io::packet::Packet;
use std::sync::atomic::Ordering;
use hytale_core::hytale_server::{HytaleServer, BOOTED, SHUTTING_DOWN};
use protocol::packets::connection::{ClientType, Connect};
use crate::connection_manager::ConnectionContext;
use crate::handle_packet;
use crate::handlers::handshake_handler::HandshakePacketHandler;
use crate::packet::packet_handler::{HandlerAction, PacketHandler};
use crate::server_network_manager::PROTOCOL_CRC;

pub struct InitialPacketHandler {}

#[async_trait::async_trait]
impl PacketHandler for InitialPacketHandler {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> HandlerAction {
        cx.clear_timeout().await;
        match packet_id {
            0 => handle_packet!(self, Connect, data, handle_connect, cx),
            _ => HandlerAction::Error(format!("Unexpected packet {} in Handshake", packet_id)),
        }
    }

    async fn register(&mut self, cx: &mut ConnectionContext) {
        cx.set_timeout(HytaleServer::get().config.read().await.timeouts.initial).await;
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

        // TODO: Editor Client
        if matches!(packet.client_type, ClientType::Game) {
            // TODO: check if universe reached max players limit
            return HandlerAction::Transition(Box::new(
                HandshakePacketHandler { connect: packet }
            ))
        }

        HandlerAction::Disconnect("Editor Client is not supported yet.".into())
    }
}