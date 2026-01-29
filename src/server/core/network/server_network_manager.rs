use std::any::Any;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;
use log::{error, info};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use quinn::{congestion, Connecting, ConnectionError, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::Certificate;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, TrustAnchor, UnixTime};
use rustls::server::{ClientCertVerifierBuilder, NoClientAuth, WebPkiClientVerifier};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio::time::timeout;
use uuid::Uuid;
use crate::server::core::hytale_server::{HytaleServer, HYTALE_SERVER};
use crate::server::core::hytale_server_config::ConnectionTimeouts;
use crate::server::core::network::auth::server_auth_manager::{ServerAuthManager};
use crate::server::core::network::auth::services::session_service::SessionService;
use crate::server::core::network::connection_manager::{Connection, ConnectionContext};
use crate::server::core::network::handlers::initial_handler::InitialPacketHandler;
use crate::server::core::network::packet::packet_error::PacketError;
use crate::server::core::network::utils::client_verifier::ClientVerifier;
use crate::server::core::network::utils::rate_limiter::RateLimiter;
use crate::server::core::network::utils::stage_timer::StageTimer;

pub static SERVER_NETWORK_MANAGER: OnceCell<ServerNetworkManager> = OnceCell::new();
pub const PROTOCOL_CRC: i32 = 1789265863;
const PROTOCOLS: &[&[u8]] = &[b"hytale/2", b"hytale/1"];
const PORT: &str = "5520";

pub struct ServerNetworkManager {
    pub endpoint: Endpoint,
    pub(crate) server_certificate: CertificateDer<'static>
}

impl ServerNetworkManager {
    pub async fn init() -> Result<(), Box<dyn Error>> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (cert, key) = generate_self_signed_cert()?;
        let server_config = build_server_config(cert.clone(), key)?;

        let addr = format!("[::]:{PORT}").parse()?;
        let endpoint = Endpoint::server(server_config, addr)?;
        let manager = ServerNetworkManager {
            endpoint,
            server_certificate: cert
        };

        let _ = SERVER_NETWORK_MANAGER.set(manager);

        ServerAuthManager::init().await;

        tokio::spawn(run_accept_loop(SERVER_NETWORK_MANAGER.get().unwrap()));
        info!("Server is listening on port {PORT}");

        Ok(())
    }
}

async fn run_accept_loop(manager: &ServerNetworkManager) {
    loop {
        match manager.endpoint.accept().await {
            Some(incoming) => match incoming.accept() {
                Ok(connection) => tokio::spawn(handle_connection(connection)),
                Err(err) => {
                    error!("Failed to accept an incoming connection: {}", err);
                    continue
                }
            },
            None => {
                // Shutdown
                error!("Endpoint closed!");
                break
            }
        };
    }
}

async fn handle_connection(connecting: Connecting) {
    let connection = match connecting.await {
        Ok(c) => c,
        Err(e) => {
            error!("Connection failed: {e}");
            return;
        }
    };

    let remote_addr = connection.remote_address();
    let connection_id = Uuid::new_v4().to_string();

    info!("New connection from {}: {}", remote_addr, connection_id);

    let client_cert = match connection.peer_identity().map(|p| p.downcast::<Vec<CertificateDer>>()) {
        Some(Ok(cert)) => *cert,
        _ => {
            error!("Connection rejected: no client certificate from {}", remote_addr);
            return;
        }
    };

    // Wait for stream
    match timeout(ConnectionTimeouts::stream_timeout(), connection.accept_bi()).await {
        Ok(Ok((send, recv))) => {
            let initial_packet_handler = Box::new(InitialPacketHandler {});

            let rate_limiter = {
                let config = HYTALE_SERVER.config.read().await;
                RateLimiter::new(
                    config.rate_limit.max_tokens,
                    config.rate_limit.refill_rate,
                )
            };

            let context = ConnectionContext {
                writer: tokio::sync::Mutex::new(send),
                timer: tokio::sync::Mutex::new(StageTimer::new(None)),
                client_cert
            };

            let conn = Connection {
                id: connection_id,
                address: remote_addr,
                handler: initial_packet_handler,
                rate_limiter,
                context
            };

            conn.run(recv).await;
        }
        Ok(Err(ConnectionError::ConnectionClosed(_))) => { info!("Connection closed!") }
        Ok(Err(e)) => error!("Connection stream error: {}", e),
        Err(_) => error!("Timed out waiting for a stream from the client!!!")
    }
}

fn build_server_config(cert_chain: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> anyhow::Result<ServerConfig> {
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(ClientVerifier))
        .with_single_cert(vec![cert_chain], key)?;

    tls.alpn_protocols = PROTOCOLS.to_vec().iter().map(|b| b.to_vec()).collect();

    let quic_config = QuicServerConfig::try_from(tls)?;
    let transport_config = build_transport_config()?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_config));
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

fn build_transport_config() -> anyhow::Result<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(1u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.receive_window(524_288u32.into());
    transport.stream_receive_window(131_072u32.into());

    let play_timeout = ConnectionTimeouts::max_idle_timeout();
    transport.max_idle_timeout(Some(play_timeout.try_into()?));

    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

    Ok(transport)
}

fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().to_owned();
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der())?;
    Ok((cert_der, key_der))
}