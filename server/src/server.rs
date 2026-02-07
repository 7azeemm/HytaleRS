use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use tokio::sync::RwLock;
use tokio::time::sleep;
use crate::command::command_manager::CommandManager;
use crate::config;
use crate::config::HytaleServerConfig;
use crate::event::event_bus::EVENT_BUS;
use crate::event::events::load_asset_event::LoadAssetEvent;
use crate::plugin::plugin_manager::PluginManager;

static HYTALE_SERVER: OnceCell<HytaleServer> = OnceCell::new();
pub static BOOTED: AtomicBool = AtomicBool::new(false);
pub static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);
static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

pub const VERSION: &str = "2026.01.24-6e2d4fc36";

#[derive(Debug)]
pub struct HytaleServer {
    pub plugin_manager: Mutex<PluginManager>,
    pub command_manager: Mutex<CommandManager>,
    pub config: RwLock<HytaleServerConfig>,
}

impl HytaleServer {
    pub async fn init() {
        let config = config::load();

        HYTALE_SERVER.set(Self {
                plugin_manager: Mutex::new(PluginManager{}),
                command_manager: Mutex::new(CommandManager{}),
                config: RwLock::new(config),
        }).unwrap();
    }
    
    pub async fn boot(&self) {
        EVENT_BUS.dispatch(&LoadAssetEvent{}).await;
        BOOTED.store(true, Ordering::Relaxed);
    }

    pub async fn start(&self) {
        while !SHOULD_STOP.load(Ordering::Relaxed) {
            sleep(Duration::from_millis(50)).await;
        }
        SHOULD_STOP.store(true, Ordering::Relaxed);
    }

    pub fn get() -> &'static HytaleServer {
        HYTALE_SERVER.get().unwrap()
    }
}