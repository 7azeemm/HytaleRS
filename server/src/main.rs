use crate::assets::asset_module::ASSET_MODULE;
use crate::assets::asset_registry::STORE_REGISTRY;
use crate::assets::common::common_module::COMMON_ASSET_MODULE;
use crate::net::server_network_manager::ServerNetworkManager;
use log::info;
use server::HytaleServer;
use std::time::Instant;
use utils::logger::Logger;
use utils::options;

pub mod assets;
pub mod command;
pub mod config;
pub mod event;
pub mod net;
pub mod plugin;
pub mod server;
pub mod utils;

#[tokio::main]
async fn main() {
    let boot_start = Instant::now();
    options::parse();
    Logger::init();

    info!("Booting HytaleRS Server...");
    HytaleServer::init().await;
    ServerNetworkManager::init().await;

    STORE_REGISTRY.register_stores().await;
    ASSET_MODULE.init().await;
    COMMON_ASSET_MODULE.init().await;

    HytaleServer::get().boot().await;
    info!("Server took {:.2?} to boot", boot_start.elapsed());

    HytaleServer::get().start().await;
    info!("Server Stopped")
}
