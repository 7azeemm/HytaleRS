use crate::utils::io::codec::iso8601_duration;
use std::time::{Duration, Instant};
use ahash::HashMap;
use log::info;
use semver::VersionReq;
use serde::{Deserialize, Serialize};
use crate::plugin::plugin_identifier::PluginIdentifier;
use crate::utils::io::json_config::JsonConfig;

const CONFIG_PATH: &str = "config.json";
const VERSION: u32 = 3;
const DEFAULT_SERVER_NAME: &str = "HytaleRS Server";
const DEFAULT_MAX_PLAYERS: u32 = 100;
const DEFAULT_MAX_VIEW_RADIUS: u32 = 32;

// NOTE: All structs in config should have #[serde(default)]

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct HytaleServerConfig {
    pub version: u32,
    pub server_name: String,
    #[serde(rename = "MOTD")]
    pub motd: String,
    pub password: String,
    pub max_players: u32,
    pub max_view_radius: u32,
    pub defaults: Defaults,
    pub timeouts: ConnectionTimeouts,
    pub rate_limit: RateLimitConfig,
    pub modules: HashMap<String, Module>,
    pub log_levels: HashMap<LogLevel, String>,
    pub mods: HashMap<PluginIdentifier, ModConfig>,
    pub display_tmp_tags_in_strings: bool,

    // pub player_storage: ,
    pub auth_credential_store_path: String,
}

impl Default for HytaleServerConfig {
    fn default() -> Self {
        Self {
            version: VERSION,
            server_name: DEFAULT_SERVER_NAME.to_owned(),
            motd: String::new(),
            password: String::new(),
            max_players: DEFAULT_MAX_PLAYERS,
            max_view_radius: DEFAULT_MAX_VIEW_RADIUS,
            defaults: Defaults::default(),
            timeouts: ConnectionTimeouts::default(),
            rate_limit: RateLimitConfig::default(),
            modules: HashMap::default(),
            log_levels: HashMap::default(),
            mods: HashMap::default(),
            display_tmp_tags_in_strings: false,
            auth_credential_store_path: "auth.enc".to_string()
        }
    }
}

pub fn load() -> HytaleServerConfig {
    info!("Loading Config...");
    let config_time = Instant::now();
    
    let config = JsonConfig::load(CONFIG_PATH, true).expect("Failed to load server config");
    JsonConfig::save(CONFIG_PATH, &config, true);
    
    info!("Config Loaded in {:.2?}", config_time.elapsed());
    config
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct Defaults {
    pub world: String,
    pub game_mode: GameMode
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            world: "default".to_owned(),
            game_mode: GameMode::Adventure,
        }
    }
}

//TODO: in com.hypixel.hytale.protocol.io.ProtocolException
#[derive(Serialize, Deserialize, Debug)]
#[derive(PartialEq)]
pub enum GameMode {
    Adventure,
    Creative
}

// TODO: try DateTime<Utc> instead of Duration (could work without the convertor)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConnectionTimeouts {
    #[serde(with = "iso8601_duration")]
    pub initial: Duration,
    #[serde(with = "iso8601_duration")]
    pub auth: Duration,
    #[serde(with = "iso8601_duration")]
    pub auth_grant: Duration,
    #[serde(with = "iso8601_duration")]
    pub auth_token: Duration,
    #[serde(with = "iso8601_duration")]
    pub auth_server_exchange: Duration,
    #[serde(with = "iso8601_duration")]
    pub password: Duration,
    #[serde(with = "iso8601_duration")]
    pub play: Duration,
    #[serde(with = "iso8601_duration")]
    pub setup_world_settings: Duration,
    #[serde(with = "iso8601_duration")]
    pub setup_assets_request: Duration,
    #[serde(with = "iso8601_duration")]
    pub setup_send_assets: Duration,
    #[serde(with = "iso8601_duration")]
    pub setup_add_to_universe: Duration,
}

impl ConnectionTimeouts {
    pub fn max_idle_timeout() -> Duration {
        Duration::from_secs(120)
    }
    pub fn stream_timeout() -> Duration {
        Duration::from_secs(15)
    }
}

impl Default for ConnectionTimeouts {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(15),
            auth: Duration::from_secs(30),
            auth_grant: Duration::from_secs(30),
            auth_token: Duration::from_secs(30),
            auth_server_exchange: Duration::from_secs(15),
            password: Duration::from_secs(45),
            play: Duration::from_secs(60),
            setup_world_settings: Duration::from_secs(15),
            setup_assets_request: Duration::from_secs(120),
            setup_send_assets: Duration::from_secs(120),
            setup_add_to_universe: Duration::from_secs(60),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub refill_rate: u32,
    pub max_tokens: u32
}

impl RateLimitConfig {
    const DEFAULT_REFILL_RATE: u32 = 2000;
    const DEFAULT_MAX_TOKENS: u32 = 500;
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            refill_rate: Self::DEFAULT_REFILL_RATE,
            max_tokens: Self::DEFAULT_MAX_TOKENS
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Module {
    pub enabled: bool,
    pub modules: HashMap<String, Module>,
    #[serde(flatten)]
    pub document: HashMap<String, serde_json::Value>, // Extra fields
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ModConfig {
    pub enabled: bool,
    pub required_version: VersionReq,
}
