use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;
use log::{error, info};
use once_cell::sync::OnceCell;
use quinn::{congestion, Connecting, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::Certificate;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio::time::timeout;
use crate::server::core::hytale_server::{HytaleServer, HYTALE_SERVER};
use crate::server::core::network::rate_limiter::RateLimiter;

pub static SERVER_NETWORK_MANAGER: OnceCell<ServerNetworkManager> = OnceCell::new();
const PORT: &str = "5520";

#[derive(Debug)]
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

        SERVER_NETWORK_MANAGER.set(manager).expect("Server Network Manager is already initialized");

        tokio::spawn(run_accept_loop());
        info!("Server is listening...");

        Ok(())
    }
}

async fn run_accept_loop() {
    let endpoint = &SERVER_NETWORK_MANAGER.get().unwrap().endpoint;

    loop {
        let Some(incoming) = endpoint.accept().await else {
            error!("Endpoint closed!");
            break
        };

        let connecting = match incoming.accept() {
            Ok(c) => c,
            Err(err) => {
                error!("Failed to accept an incoming connection: {}", err);
                continue
            }
        };

        tokio::spawn(handle_connection(connecting));
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

    info!("Connection from {}", connection.remote_address());

    // Verify client certificate
    let identity = connection.peer_identity();
    let client_certs = identity.and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok());
    if client_certs.is_none() {
        info!("Rejected: no client certificate");
        // connection.close(0u32.into(), b"Missing client certificate");
        // return;
    }

    // Accept streams
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(handle_stream(send, recv));
            }
            Err(e) => {
                error!("Stream accept error: {e}");
                break;
            }
        }
    }
}

async fn handle_stream(mut send: SendStream, mut recv: RecvStream) {
    let mut buf = vec![0u8; 64 * 1024]; // 64 KB
    let (mut rate_limiter, read_timeout) = {
        let config = HYTALE_SERVER.config.lock();
        let rate_limiter_config = &config.rate_limit;
        let max_tokens = rate_limiter_config.max_tokens;
        let refill_tokens = rate_limiter_config.refill_rate;
        (RateLimiter::new(max_tokens, refill_tokens), config.connection_timeouts.initial_timeout)
    };

    loop {
        let n = match timeout(read_timeout, recv.read(&mut buf)).await {
            Ok(Ok(Some(n))) => n,
            Ok(Ok(None)) => {
                info!("Stream closed by client");
                break;
            }
            Ok(Err(e)) => {
                info!("Read error: {e}");
                break;
            }
            Err(_) => {
                info!("Timeout waiting for packet");
                break;
            }
        };

        if !rate_limiter.consume() {
            info!("Rate limit exceeded, disconnecting stream");
            break;
        }

        let packet_bytes = &buf[..n];
        info!("Received packet ({} bytes): {:?}", n, packet_bytes);

        // TODO: packetDecoder, packetHandler, packetEncoder will go here later
    }

    // Stream closed
    let _ = send.finish();
    info!("Stream handler finished");
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

    let play_timeout = HYTALE_SERVER.config.lock().connection_timeouts.play_timeout;
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