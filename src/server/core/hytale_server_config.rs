use crate::util::io::codec::iso8601_duration;
use std::time::Duration;
use ahash::HashMap;
use semver::VersionReq;
use serde::{Deserialize, Serialize};
use crate::plugin::plugin_identifier::PluginIdentifier;
use crate::util::io::json_config::JsonConfig;

const CONFIG_PATH: &str = "config.json";
const VERSION: u32 = 3;
const DEFAULT_SERVER_NAME: &str = "HytaleRS Server";
const DEFAULT_MAX_PLAYERS: u32 = 100;
const DEFAULT_MAX_VIEW_RADIUS: u32 = 32;

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
    pub connection_timeouts: ConnectionTimeouts,
    pub rate_limit: RateLimitConfig,
    pub modules: HashMap<String, Module>,
    pub log_levels: HashMap<LogLevel, String>,
    pub mods: HashMap<PluginIdentifier, ModConfig>,
    pub display_tmp_tags_in_strings: bool,

    // pub player_storage: ,
    // pub auth_credential_store: ,
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
            connection_timeouts: ConnectionTimeouts::default(),
            rate_limit: RateLimitConfig::default(),
            modules: HashMap::default(),
            log_levels: HashMap::default(),
            mods: HashMap::default(),
            display_tmp_tags_in_strings: false,
        }
    }
}

pub fn load() -> HytaleServerConfig {
    let config = JsonConfig::load(CONFIG_PATH, true).expect("Failed to load server config");
    JsonConfig::save(CONFIG_PATH, &config, true);
    config
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
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

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConnectionTimeouts {
    #[serde(with = "iso8601_duration")]
    pub initial_timeout: Duration,
    #[serde(with = "iso8601_duration")]
    pub auth_timeout: Duration,
    #[serde(with = "iso8601_duration")]
    pub play_timeout: Duration,
    #[serde(with = "iso8601_duration::map")]
    pub join_timeouts: HashMap<String, Duration>,
}

impl ConnectionTimeouts {
    // Play Timeout should always be the longest!
    const DEFAULT_INITIAL_TIMEOUT: Duration = Duration::from_secs(10);
    const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
    const DEFAULT_PLAY_TIMEOUT: Duration = Duration::from_secs(60);
}

impl Default for ConnectionTimeouts {
    fn default() -> Self {
        Self {
            initial_timeout: Self::DEFAULT_INITIAL_TIMEOUT,
            auth_timeout: Self::DEFAULT_AUTH_TIMEOUT,
            play_timeout: Self::DEFAULT_PLAY_TIMEOUT,
            join_timeouts: HashMap::default()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_partial() {
        let json = r#"{
            "Version": 1,
            "ServerName": "Custom Server",
            "MaxPlayers": 50
        }"#;
        let config: HytaleServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.server_name, "Custom Server");
        assert_eq!(config.max_players, 50);
        assert_eq!(config.max_view_radius, DEFAULT_MAX_VIEW_RADIUS);
    }

    #[test]
    fn test_deserialize_full_config() {
        let json = r#"{
            "Version": 1,
            "ServerName": "My Hytale Server",
            "MOTD": "Welcome to the server!",
            "Password": "secret123",
            "MaxPlayers": 100,
            "MaxViewRadius": 15,
            "Defaults": {
                "World": "custom_world",
                "GameMode": "Creative"
            },
            "ConnectionTimeouts": {
                "InitialTimeout": "PT15S",
                "AuthTimeout": "PT45S",
                "PlayTimeout": "PT2M",
                "JoinTimeouts": {
                    "world1": "PT30S",
                    "world2": "PT1M"
                }
            },
            "RateLimit": {
                "Enabled": false,
                "PacketsPerSecond": 3000,
                "BurstCapacity": 1000
            },
            "Modules": {
                "combat": {
                    "Enabled": true,
                    "Modules": {}
                }
            },
            "LogLevels": {
                "Info": "info_log.txt",
                "Error": "error_log.txt"
            },
            "Mods": {},
            "DisplayTmpTagsInStrings": true
        }"#;

        let config: HytaleServerConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.version, 1);
        assert_eq!(config.server_name, "My Hytale Server");
        assert_eq!(config.motd, "Welcome to the server!");
        assert_eq!(config.password, "secret123");
        assert_eq!(config.max_players, 100);
        assert_eq!(config.max_view_radius, 15);
        assert!(config.display_tmp_tags_in_strings);

        assert_eq!(config.defaults.world, "custom_world");
        assert_eq!(config.defaults.game_mode, GameMode::Creative);

        assert_eq!(config.connection_timeouts.initial_timeout, Duration::from_secs(15));
        assert_eq!(config.connection_timeouts.auth_timeout, Duration::from_secs(45));
        assert_eq!(config.connection_timeouts.play_timeout, Duration::from_secs(120));
        assert_eq!(config.connection_timeouts.join_timeouts.get("world1"), Some(&Duration::from_secs(30)));
        assert_eq!(config.connection_timeouts.join_timeouts.get("world2"), Some(&Duration::from_secs(60)));

        assert!(!config.rate_limit.enabled);
        assert_eq!(config.rate_limit.refill_rate, 3000);
        assert_eq!(config.rate_limit.max_tokens, 1000);

        assert!(config.modules.contains_key("combat"));
        assert!(config.modules.get("combat").unwrap().enabled);
    }

    #[test]
    fn test_serialize_then_deserialize() {
        let original = HytaleServerConfig {
            version: 2,
            server_name: "Test Server".to_string(),
            motd: "Test MOTD".to_string(),
            password: "pass".to_string(),
            max_players: 50,
            max_view_radius: 12,
            defaults: Defaults {
                world: "test_world".to_string(),
                game_mode: GameMode::Creative,
            },
            connection_timeouts: ConnectionTimeouts {
                initial_timeout: Duration::from_secs(20),
                auth_timeout: Duration::from_secs(40),
                play_timeout: Duration::from_secs(80),
                join_timeouts: {
                    let mut map = HashMap::default();
                    map.insert("world1".to_string(), Duration::from_secs(25));
                    map
                },
            },
            rate_limit: RateLimitConfig {
                enabled: false,
                refill_rate: 1500,
                max_tokens: 300,
            },
            modules: HashMap::default(),
            log_levels: HashMap::default(),
            mods: HashMap::default(),
            display_tmp_tags_in_strings: true,
        };

        let json = serde_json::to_string_pretty(&original).unwrap();
        let deserialized: HytaleServerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, original.version);
        assert_eq!(deserialized.server_name, original.server_name);
        assert_eq!(deserialized.motd, original.motd);
        assert_eq!(deserialized.max_players, original.max_players);
        assert_eq!(deserialized.defaults.world, original.defaults.world);
        assert_eq!(deserialized.defaults.game_mode, original.defaults.game_mode);
        assert_eq!(deserialized.connection_timeouts.initial_timeout, original.connection_timeouts.initial_timeout);
        assert_eq!(deserialized.rate_limit.enabled, original.rate_limit.enabled);
        assert_eq!(deserialized.display_tmp_tags_in_strings, original.display_tmp_tags_in_strings);
    }

    #[test]
    fn test_connection_timeouts_iso8601() {
        let json = r#"{
            "InitialTimeout": "PT10S",
            "AuthTimeout": "PT1M30S",
            "PlayTimeout": "PT2M",
            "JoinTimeouts": {
                "lobby": "PT5S",
                "arena": "PT15S"
            }
        }"#;

        let timeouts: ConnectionTimeouts = serde_json::from_str(json).unwrap();
        assert_eq!(timeouts.initial_timeout, Duration::from_secs(10));
        assert_eq!(timeouts.auth_timeout, Duration::from_secs(90));
        assert_eq!(timeouts.play_timeout, Duration::from_secs(120));
        assert_eq!(timeouts.join_timeouts.get("lobby"), Some(&Duration::from_secs(5)));
        assert_eq!(timeouts.join_timeouts.get("arena"), Some(&Duration::from_secs(15)));

        let serialized = serde_json::to_string(&timeouts).unwrap();
        let deserialized: ConnectionTimeouts = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.initial_timeout, timeouts.initial_timeout);
    }

    #[test]
    fn test_module_with_extra_fields() {
        let json = r#"{
            "Enabled": true,
            "Modules": {},
            "CustomField": "custom_value",
            "AnotherField": 123
        }"#;

        let module: Module = serde_json::from_str(json).unwrap();
        assert!(module.enabled);
        assert!(module.document.contains_key("CustomField") && module.document.contains_key("AnotherField"));
    }
}