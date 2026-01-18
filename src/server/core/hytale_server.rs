use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use log::info;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use tokio::time::sleep;
use crate::server::core::command::system::command_manager::CommandManager;
use crate::server::core::hytale_server_config::HytaleServerConfig;
use crate::server::core::plugin::plugin_manager::PluginManager;
use crate::event::event_bus::EventBus;
use crate::server::core::{hytale_server_config, options};

static SERVER_INSTANCE: OnceCell<Arc<HytaleServer>> = OnceCell::new();
static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct HytaleServer {
    event_bus: Mutex<EventBus>,
    plugin_manager: Mutex<PluginManager>,
    command_manager: Mutex<CommandManager>,
    hytale_server_config: Mutex<HytaleServerConfig>,
    boot_start: Instant,
}

impl HytaleServer {
    pub fn new() -> Arc<Self> {
        let boot_start = Instant::now();
        info!("Starting HytaleRS Server");

        //TODO: setup Store Providers

        info!("Loading Config...");
        let config_time = Instant::now();
        let config = hytale_server_config::load();
        info!("Config Loaded in {:.2?}", config_time.elapsed());

        info!("Authentication mode: {}", options::get().auth_mode);
        //TODO: auth

        //TODO: NettyUtil (Packet Logging?)
        //TODO: register assets
        //TODO: register core plugins

        let server = Self {
            event_bus: Mutex::new(EventBus{}),
            plugin_manager: Mutex::new(PluginManager{}),
            command_manager: Mutex::new(CommandManager{}),
            hytale_server_config: Mutex::new(config),
            boot_start,
        };

        SERVER_INSTANCE.set(Arc::new(server)).unwrap();
        SERVER_INSTANCE.get().unwrap().clone()
    }

    pub async fn start(&self) {
        while !SHOULD_STOP.load(Ordering::Relaxed) {
            sleep(Duration::from_millis(50)).await;
        }
    }
}