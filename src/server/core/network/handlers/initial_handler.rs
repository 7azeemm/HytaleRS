use std::time::Instant;
use log::{debug, info};
use crate::server::core::network::connection_manager::{Connection, ConnectionContext};
use crate::server::core::network::handlers::authentication_handler::AuthenticationPacketHandler;
use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_codec::{CodecError, PacketCodec};
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};
use crate::server::core::network::packet::packets::connect::{Connect};

pub struct InitialPacketHandler {}

#[async_trait::async_trait]
impl PacketHandler for InitialPacketHandler {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> Result<HandlerAction, String> {
        match packet_id {
            0x00 => {
                info!("Packet Received in InitialHandler: {packet_id}");

                let j = Instant::now();
                let packet = Connect::decode(data).unwrap();
                println!("{:?}", j.elapsed());
                dbg!(packet);

                // Logic: Transition to Auth
                Ok(HandlerAction::Transition(Box::new(AuthenticationPacketHandler {})))
            },
            0x01 => Ok(HandlerAction::Disconnect("Client quit".into())),
            _ => Err(format!("Unexpected packet 0x{:02X} in Handshake", packet_id)),
        }
    }
}
