use std::error::Error;
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use log::{error, info, warn};
use parking_lot::Mutex;
use quinn::{RecvStream, SendStream};
use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_codec::{PacketCodec};
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};
use crate::server::core::network::rate_limiter::RateLimiter;

pub struct Connection {
    pub id: String,
    pub address: SocketAddr,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub context: ConnectionContext,
    pub handler: Box<dyn PacketHandler>,
}

impl Connection {
    pub async fn run(mut self, mut recv: RecvStream) {
        loop {
            // 1. Read framed packet
            let data = match PacketCodec::read_framed_packet(&mut recv).await {
                Ok(d) => d,
                Err(e) => {
                    info!("Connection {} closed: {}", self.address, e);
                    break;
                }
            };

            if !self.rate_limiter.lock().consume() {
                warn!("RateLimited connection {}", self.address);
                continue
            }

            // 2. Extract ID
            if data.len() < 4 {
                error!("Packet too short: {} bytes", data.len());
                continue;
            }
            let packet_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            info!("Received Packet {}", packet_id);

            // 3. Pass only the body (skip first 4 bytes of packet ID)
            let body = &data[4..];

            // 3. Handle
            match self.handler.handle(packet_id, body, &mut self.context).await {
                Ok(HandlerAction::Continue) => {},
                Ok(HandlerAction::Transition(new_handler)) => {
                    log::debug!("Transitioning state for {}", self.address);
                    self.handler = new_handler;
                },
                Ok(HandlerAction::Disconnect(reason)) => {
                    info!("Disconnecting {}: {}", self.address, reason);
                    self.context.disconnect(&reason).await;
                    break;
                },
                Err(e) => {
                    error!("Protocol error: {}", e);
                    self.context.disconnect("Protocol Error").await;
                    break;
                }
            }
        }
    }
}

pub struct ConnectionContext {
    pub writer: Arc<Mutex<SendStream>>,
}

impl ConnectionContext {
    pub async fn send<P: Packet>(&self, packet: &P) -> Result<(), Box<dyn Error>> {
        let bytes = PacketCodec::encode_packet(packet)?;
        let mut writer = self.writer.lock();
        writer.write_all(&bytes).await?;
        Ok(())
    }

    pub async fn disconnect(&self, reason: &str) {
        error!("Disconnecting..., reason: {}", reason);
        let _ = self.writer.lock().finish();
    }
}
