use log::info;
use crate::logger::hytale_logger;
use crate::server::core::hytale_server::HytaleServer;
use crate::server::core::options;

mod logger;
mod server;
mod event;

#[tokio::main]
async fn main() {
    options::parse();
    hytale_logger::init().expect("Failed to setup logger");
    let server = HytaleServer::new();

    server.start().await;
    info!("Server Stopped")
}
