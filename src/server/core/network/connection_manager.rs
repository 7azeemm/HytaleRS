use std::error::Error;
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use log::{debug, error, info, warn};
use parking_lot::Mutex;
use quinn::{ReadError, ReadExactError, RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use tokio::time::timeout;
use crate::protocol::packets::connection::disconnect::{Disconnect, DisconnectCause};
use crate::server::core::hytale_server::HYTALE_SERVER;
use crate::server::core::hytale_server_config::ConnectionTimeouts;
pub(crate) use crate::server::core::network::packet::MAX_PACKET_SIZE;
use crate::server::core::network::packet::packet::Packet;
use crate::server::core::network::packet::packet_error::{PacketError};
use crate::server::core::network::packet::packet_decoder::{read_framed_packet, PacketDecoder};
use crate::server::core::network::packet::packet_encoder::PacketEncoder;
use crate::server::core::network::packet::packet_handler::{HandlerAction, PacketHandler};
use crate::server::core::network::utils::rate_limiter::RateLimiter;
use crate::server::core::network::utils::stage_timer::StageTimer;

pub struct Connection {
    pub id: String,
    pub address: SocketAddr,
    pub rate_limiter: RateLimiter,
    pub context: ConnectionContext,
    pub handler: Box<dyn PacketHandler>,
}

impl Connection {
    pub async fn run(mut self, mut recv: RecvStream) {
        self.handler.register(&mut self.context).await;
        
        loop {
            if self.context.check_timeout().await { break }

            // Rate limiting
            if !self.rate_limiter.consume() {
                warn!("Rate limit exceeded for {}", self.address);
                continue;
            }

            let read_result = match self.context.read_timeout().await {
                Some(duration) => {
                    tokio::time::timeout(duration, read_framed_packet(&mut recv))
                        .await
                        .map_err(|_| PacketError::ConnectionLost)
                        .and_then(|r| r)
                }
                None => read_framed_packet(&mut recv).await,
            };

            match read_result {
                Ok((packet_id, body)) => {
                    // Handle disconnect packet
                    if packet_id == 0x01 {
                        let reason = match PacketDecoder::decode::<Disconnect>(&body) {
                            Some(packet) => packet.reason.unwrap_or_else(|| packet.cause.to_string()),
                            None => "Unknown".to_owned()
                        };

                        info!("Client disconnected, reason: {}", reason);
                        self.context.close().await;
                        break;
                    }

                    info!("Received Packet 0x{:02X} from {}", packet_id, self.address);

                    // Handle packet
                    match self.handler.handle(packet_id, &body, &mut self.context).await {
                        HandlerAction::Continue => {},
                        HandlerAction::Transition(new_handler) => {
                            info!("Handler changed for {}", self.address);
                            self.handler = new_handler;
                            self.handler.register(&mut self.context).await;
                        },
                        HandlerAction::Disconnect(reason) => {
                            self.context.disconnect(&reason).await;
                            break;
                        },
                        HandlerAction::Error(error) => {
                            error!("Protocol Error: {}", error);
                            self.context.disconnect("Protocol Error").await;
                            break;
                        }
                    }
                }
                Err(e) => {
                    match e {
                        PacketError::ConnectionLost => info!("Connection closed: {}", self.address),
                        _ => error!("Read error: {} from {}", e, self.address)
                    }
                    break;
                }
            }
        }
    }
}

pub struct ConnectionContext {
    pub writer: tokio::sync::Mutex<SendStream>,
    pub timer: tokio::sync::Mutex<StageTimer>,
    pub(crate) client_cert: Vec<CertificateDer<'static>>
}

impl ConnectionContext {
    pub async fn send<P: Packet>(&self, packet: P) -> Option<()> {
        let bytes = PacketEncoder::encode(&packet)?;
        let mut writer = self.writer.lock().await;
        if let Err(err) = writer.write_all(&bytes).await {
            error!("Failed to write packet 0x{:02X}: {}", P::packet_id(), err);
            return None
        }
        info!("Sent Packet 0x{:02X}", P::packet_id());
        Some(())
    }

    // Todo: maybe can be non-async and spawns a tokio thread to send the packet
    pub async fn disconnect(&self, reason: &str) {
        info!("Disconnecting..., reason: {}", reason);
        self.send(Disconnect {
            reason: Some(reason.to_owned()),
            cause: DisconnectCause::Disconnect
        }).await;
        self.close().await;
    }

    pub async fn set_timeout(&self, timeout: Duration) {
        info!("Timeout is set to {:?}", timeout);
        *self.timer.lock().await = StageTimer::new(Some(timeout));
    }

    pub async fn clear_timeout(&self) {
        info!("Timeout is cleared");
        *self.timer.lock().await = StageTimer::new(None);
    }

    pub async fn read_timeout(&self) -> Option<Duration> {
        self.timer.lock().await.remaining_time()
    }

    pub async fn check_timeout(&self) -> bool {
        let timer = self.timer.lock().await;
        if timer.is_timed_out() {
            info!("Handler timeout after {:.2?}", timer.elapsed());
            return true
        }
        false
    }

    pub async fn close(&self) {
        let _ = self.writer.lock().await.finish();
    }
}
