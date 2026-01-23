use std::error::Error;
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use log::{error, info, warn};
use parking_lot::Mutex;
use quinn::{ReadError, ReadExactError, RecvStream, SendStream};
use crate::protocol::packets::disconnect::{Disconnect, DisconnectCause};
use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_error::{PacketError};
use crate::server::core::network::packet::packet_decoder::PacketDecoder;
use crate::server::core::network::packet::packet_encoder::PacketEncoder;
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};
use crate::server::core::network::rate_limiter::RateLimiter;

pub const MAX_PACKET_SIZE: usize = 262_144; // 256 KB

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
            let (packet_id, body) = match read_framed_packet(&mut recv).await {
                Ok(d) => d,
                Err(e) => {
                    if matches!(e, PacketError::ConnectionLost) {
                        info!("Connection {} closed", self.address);
                    } else {
                        error!("Connection {} closed: {}", self.address, e);
                    }
                    break;
                }
            };

            if !self.rate_limiter.lock().consume() {
                warn!("Rate limit exceeded for {}", self.address);
                continue
            }

            info!("Received Packet ID: 0x{:02X}", packet_id);

            if packet_id == 0x01 {
                let reason = match PacketDecoder::decode::<Disconnect>(&body) {
                    Some(packet) => packet.reason.unwrap_or_else(|| packet.cause.to_string()),
                    None => "Unknown".to_owned()
                };

                info!("Disconnecting..., reason: {}", reason);
                self.context.close().await;
                break;
            }

            match self.handler.handle(packet_id, &body, &mut self.context).await {
                Ok(HandlerAction::Continue) => {},
                Ok(HandlerAction::Transition(new_handler)) => {
                    info!("Transitioning state for {}", self.address);
                    self.handler = new_handler;
                },
                Ok(HandlerAction::Disconnect(reason)) => {
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
    pub writer: Arc<tokio::sync::Mutex<SendStream>>,
}

impl ConnectionContext {
    pub async fn send<P: Packet>(&self, packet: &P) -> Option<()> {
        let bytes = PacketEncoder::encode(packet)?;
        let mut writer = self.writer.lock().await;
        if let Err(err) = writer.write_all(&bytes).await {
            error!("Failed to write packet 0x{:02X}: {}", P::packet_id(), err);
            return None
        }
        info!("Sent Packet 0x{:02X}", P::packet_id());
        Some(())
    }

    pub async fn disconnect(&self, reason: &str) {
        info!("Disconnecting..., reason: {}", reason);
        self.send(&Disconnect {
            reason: Some(reason.to_owned()),
            cause: DisconnectCause::Disconnect
        }).await;
        self.close().await;
    }

    pub async fn close(&self) {
        let _ = self.writer.lock().await.finish();
    }
}

/// Read framed packet from stream
/// Returns: (packet_id, body_bytes)
pub async fn read_framed_packet(recv: &mut RecvStream) -> Result<(u32, Vec<u8>), PacketError> {
    let mut header = [0u8; 8];
    if let Err(err) = recv.read_exact(&mut header).await {
        return Err(match err {
            ReadExactError::ReadError(read_err) => match read_err {
                ReadError::ConnectionLost(_) | ReadError::ClosedStream => PacketError::ConnectionLost,
                _ => PacketError::Decode(format!("Failed to read packet header: {}", read_err)),
            },
            _ => PacketError::Decode(format!("Failed to read packet header: {}", err)),
        })
    }

    let payload_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let packet_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

    if payload_len == 0 {
        return Err(PacketError::Decode("Empty packet payload".into()));
    }
    if payload_len > MAX_PACKET_SIZE {
        return Err(PacketError::TooLarge(format!(
            "Packet payload {} exceeds max size {}",
            payload_len, MAX_PACKET_SIZE
        )));
    }

    let mut payload = vec![0u8; payload_len];
    recv.read_exact(&mut payload).await
        .map_err(|e| PacketError::Decode(format!("Failed to read packet payload: {}", e)))?;

    Ok((packet_id, payload))
}