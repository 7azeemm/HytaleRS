use crate::net::handlers::packet_handler::{HandlerAction, PacketHandler};
use crate::net::utils::packet_io::{decode, read_packet, write_packet};
use crate::net::utils::rate_limiter::RateLimiter;
use crate::net::utils::stage_timer::StageTimer;
use log::{error, info, warn};
use protocol::io::packet::Packet;
use protocol::packets::connection::{Disconnect, DisconnectCause};
use quinn::{RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use std::error::Error;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

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
            if self.context.check_timeout().await {
                break;
            }

            // Rate limiting
            if !self.rate_limiter.consume() {
                warn!("Rate limit exceeded for {}", self.address);
                continue;
            }

            let read_result = match self.context.read_timeout().await {
                Some(duration) => timeout(duration, read_packet(&mut recv)).await,
                None => Ok(read_packet(&mut recv).await),
            };

            match read_result {
                Ok(Ok((packet_id, body))) => {
                    // Handle disconnect packet
                    if packet_id == 0x01 {
                        let reason = match decode::<Disconnect>(&body) {
                            Some(packet) => {
                                packet.reason.unwrap_or_else(|| packet.cause.to_string())
                            }
                            None => "Unknown".to_owned(),
                        };

                        info!("Client disconnected, reason: {}", reason);
                        self.context.close().await;
                        break;
                    }

                    // Handle packet
                    match self
                        .handler
                        .handle(packet_id, &body, &mut self.context)
                        .await
                    {
                        HandlerAction::Continue => {}
                        HandlerAction::Transition(new_handler) => {
                            info!("Handler changed for {}", self.address);
                            self.handler = new_handler;
                            self.handler.register(&mut self.context).await;
                        }
                        HandlerAction::Disconnect(reason) => {
                            self.context.disconnect(&reason).await;
                            break;
                        }
                        HandlerAction::Error(error) => {
                            error!("Protocol Error: {}", error);
                            self.context.disconnect("Protocol Error").await;
                            break;
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Read Error: {} from {}", e, self.address);
                    break;
                }
                Err(_) => {
                    info!("Connection closed: {}", self.address);
                    break;
                }
            }
        }
    }
}

pub struct ConnectionContext {
    pub writer: tokio::sync::Mutex<SendStream>,
    pub timer: tokio::sync::Mutex<StageTimer>,
    pub(crate) client_cert: Vec<CertificateDer<'static>>,
}

impl ConnectionContext {
    pub async fn send<P: Packet>(&self, packet: P) {
        let bytes = match write_packet(&packet) {
            Ok(b) => b,
            Err(err) => {
                error!("{}: {}", P::name(), err);
                return;
            }
        };
        let mut writer = self.writer.lock().await;
        if let Err(err) = writer.write_all(&bytes).await {
            error!("Failed to write packet {}: {}", P::name(), err);
            return;
        }
        info!("Sent Packet {}", P::name());
    }

    // Todo: maybe can spawns a tokio task to send the packet
    pub async fn disconnect(&self, reason: &str) {
        info!("Disconnecting..., reason: {}", reason);
        self.send(Disconnect {
            cause: DisconnectCause::Disconnect,
            reason: Some(reason.to_owned()),
        })
        .await;
        self.close().await;
    }

    pub async fn set_timeout(&self, timeout: Duration) {
        *self.timer.lock().await = StageTimer::new(Some(timeout));
    }

    pub async fn clear_timeout(&self) {
        *self.timer.lock().await = StageTimer::new(None);
    }

    pub async fn read_timeout(&self) -> Option<Duration> {
        self.timer.lock().await.remaining_time()
    }

    pub async fn check_timeout(&self) -> bool {
        let timer = self.timer.lock().await;
        if timer.is_timed_out() {
            info!("Handler timeout after {:.2?}", timer.elapsed());
            return true;
        }
        false
    }

    pub async fn close(&self) {
        let _ = self.writer.lock().await.finish();
    }
}
