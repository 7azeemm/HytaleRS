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
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio::time::timeout;
use uuid::Uuid;
use crate::server::core::hytale_server::{HytaleServer, HYTALE_SERVER};
use crate::server::core::network::connection_manager::{Connection, ConnectionContext};
use crate::server::core::network::handlers::initial_handler::InitialPacketHandler;
use crate::server::core::network::packet::packet_error::PacketError;
use crate::server::core::network::rate_limiter::RateLimiter;

pub static SERVER_NETWORK_MANAGER: OnceCell<ServerNetworkManager> = OnceCell::new();
const PORT: &str = "5520";

pub struct ServerNetworkManager {
    pub endpoint: Endpoint,
}

impl ServerNetworkManager {
    pub fn init() -> Result<(), Box<dyn Error>> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (cert, key) = generate_self_signed_cert()?;
        let server_config = build_server_config(cert, key)?;

        let addr = format!("[::]:{PORT}").parse()?;
        let endpoint = Endpoint::server(server_config, addr)?;
        let manager = ServerNetworkManager { endpoint };

        if let Err(_) = SERVER_NETWORK_MANAGER.set(manager) {
            panic!("Server Network Manager already initialized")
        }

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

    let rate_limiter = Arc::new(Mutex::new({
        let config = HYTALE_SERVER.config.read();
        RateLimiter::new(
            config.rate_limit.max_tokens,
            config.rate_limit.refill_rate,
        )
    }));

    // Accept streams
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let initial_packet_handler = Box::new(InitialPacketHandler {});
                let conn = Connection {
                    id: connection_id.clone(),
                    address: remote_addr,
                    rate_limiter: rate_limiter.clone(),
                    handler: initial_packet_handler,
                    context: ConnectionContext {
                        writer: Arc::new(tokio::sync::Mutex::new(send))
                    }
                };
                tokio::spawn(conn.run(recv));
            }
            Err(e) if !matches!(ConnectionError::ConnectionClosed, _e) => {
                error!("Stream Error: {}", e);
                break;
            }
            Err(_) => { /* Disconnect */ }
        }
    }
}

fn build_server_config(cert_chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> anyhow::Result<ServerConfig> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        // .with_client_cert_verifier(Arc::new(InsecureClientVerifier))
        .with_single_cert(cert_chain, key)?;

    tls.alpn_protocols = vec![b"hytale/1".to_vec()];

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

    let play_timeout = HYTALE_SERVER.config.read().connection_timeouts.play_timeout;
    transport.max_idle_timeout(Some(play_timeout.try_into()?));

    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

    Ok(transport)
}

fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = vec![cert.cert.der().to_owned()];
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der())?;
    Ok((cert_der, key_der))
}