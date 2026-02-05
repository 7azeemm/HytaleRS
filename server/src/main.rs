use std::sync::LazyLock;
use std::time::Instant;
use log::info;
use assets::asset_module::ASSET_MODULE;
use assets::asset_registry::STORE_REGISTRY;
use assets::common::common_module::COMMON_ASSET_MODULE;
use hytale_core::hytale_server::HytaleServer;
use hytale_core::utils::hytale_logger::Logger;
use hytale_core::utils::options;
use net::server_network_manager::ServerNetworkManager;

#[tokio::main]
async fn main() {
    let boot_start = Instant::now();
    options::parse();
    Logger::init();

    info!("Booting HytaleRS Server...");
    HytaleServer::init().await;
    ServerNetworkManager::init().await;

    STORE_REGISTRY.register_stores();
    ASSET_MODULE.init().await;
    COMMON_ASSET_MODULE.init().await;

    HytaleServer::get().boot().await;
    info!("Server took {:.2?} to boot", boot_start.elapsed());

    HytaleServer::get().start().await;
    info!("Server Stopped")
}
