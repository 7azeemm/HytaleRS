use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use log::info;
use parking_lot::Mutex;
use tokio::time::sleep;
use crate::server::core::command::system::command_manager::CommandManager;
use crate::server::core::hytale_server_config::HytaleServerConfig;
use crate::server::core::plugin::plugin_manager::PluginManager;
use crate::event::event_bus::EventBus;
use crate::server::core::{hytale_server_config, options};
use crate::server::core::network::server_network_manager::ServerNetworkManager;

pub static HYTALE_SERVER: LazyLock<Arc<HytaleServer>> = LazyLock::new(|| Arc::new(HytaleServer::new()));
static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct HytaleServer {
    pub event_bus: Mutex<EventBus>,
    pub plugin_manager: Mutex<PluginManager>,
    pub command_manager: Mutex<CommandManager>,
    pub config: Mutex<HytaleServerConfig>,
    boot_start: Instant,
}

impl HytaleServer {
    fn new() -> Self {
        let boot_start = Instant::now();
        info!("Starting HytaleRS Server...");

        info!("Loading Config...");
        let config_time = Instant::now();
        let config = hytale_server_config::load();
        info!("Config Loaded in {:.2?}", config_time.elapsed());
        info!("Authentication mode: {}", options::get().auth_mode);

        Self {
            event_bus: Mutex::new(EventBus{}),
            plugin_manager: Mutex::new(PluginManager{}),
            command_manager: Mutex::new(CommandManager{}),
            config: Mutex::new(config),
            boot_start,
        }
    }
    
    pub fn init(&self) {
        ServerNetworkManager::init().expect("Failed to initialize Server Network Manager");

        //TODO: auth
        //TODO: NettyUtil (Packet Logging?)
        //TODO: register assets
        //TODO: register core plugins

        info!("Server took {:.2?} to start", self.boot_start.elapsed());
    }

    pub async fn start(&self) {
        while !SHOULD_STOP.load(Ordering::Relaxed) {
            sleep(Duration::from_millis(50)).await;
        }
    }
}