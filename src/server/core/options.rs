use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use clap::{Parser, ValueEnum};
use once_cell::sync::OnceCell;

static OPTIONS: OnceCell<Arc<Options>> = OnceCell::new();

#[derive(Parser, Debug)]
#[command(name = "HytaleRS", disable_help_flag = true)]
pub struct Options {
    #[arg(long, help = "Print's this message.")]
    pub help: bool,

    #[arg(long, help = "Prints version information.")]
    pub version: bool,

    #[arg(long, help = "Runs the server bare. For example without loading worlds, binding to ports or creating directories. (Note: Plugins will still be loaded which may not respect this flag)")]
    pub bare: bool,

    #[arg(long, value_delimiter = ',', help = "Sets the logger level.")]
    pub log: Vec<String>,

    #[arg(short = 'b', long = "bind", default_value = "0.0.0.0:5520", help = "Port to listen on")]
    pub bind: SocketAddr,

    #[arg(short = 't', long = "transport", value_enum, default_value = "quic", help = "Transport type")]
    pub transport: TransportType,

    #[arg(long, help = "Disables building of compact prefab buffers")]
    pub disable_cpb_build: bool,

    #[arg(long, help = "Prefab cache directory for immutable assets")]
    pub prefab_cache: Option<PathBuf>,

    #[arg(long, help = "Asset directory", value_parser = parse_dir_or_zip, default_value = "../HytaleAssets")]
    pub assets: PathBuf,

    #[arg(long, help = "Additional mods directories", value_parser = parse_dir, value_delimiter = ',')]
    pub mods: Vec<PathBuf>,

    #[arg(long, help = "You acknowledge that loading early plugins is unsupported and may cause stability issues.")]
    pub accept_early_plugins: bool,

    #[arg(long, help = "Additional early plugin directories to load from", value_parser = parse_dir, value_delimiter = ',')]
    pub early_plugins: Vec<PathBuf>,

    #[arg(long, help = "Causes the server to exit with an error code if any assets are invalid.")]
    pub validate_assets: bool,

    #[arg(long, help = "Causes the server to exit with an error code if any prefabs are invalid.")]
    pub validate_prefabs: Option<ValidationOption>,

    #[arg(long, help = "Causes the server to exit with an error code if default world gen is invalid.")]
    pub validate_world_gen: bool,

    #[arg(long, help = "Automatically shutdown the server after asset and/or prefab validation.")]
    pub shutdown_after_validate: bool,

    #[arg(long, help = "Causes the server generate schema, save it into the assets directory and then exit")]
    pub generate_schema: bool,

    #[arg(long, help = "World gen directory", value_parser = parse_dir)]
    pub world_gen: Option<PathBuf>,

    #[arg(long, help = "Disables file watcher")]
    pub disable_file_watcher: bool,

    #[arg(long, help = "Disables asset comparison")]
    pub disable_asset_compare: bool,

    #[arg(long, help = "Backup the server")]
    pub backup: bool,

    #[arg(long, help = "Backup frequency in minutes", default_value_t = 30)]
    pub backup_frequency: u32,

    #[arg(long, help = "Backup directory", value_parser = parse_dir, required_if_eq("backup", "true"))]
    pub backup_dir: Option<PathBuf>,

    #[arg(long, help = "Maximum number of backups to keep", default_value_t = 5)]
    pub backup_max_count: u32,

    #[arg(long, help = "Singleplayer mode")]
    pub singleplayer: bool,

    #[arg(long, help = "Owner name")]
    pub owner_name: Option<String>,

    #[arg(long, help = "Owner UUID")]
    pub owner_uuid: Option<String>,

    #[arg(long, help = "Client PID")]
    pub client_pid: Option<u32>,

    #[arg(long, help = "Universe directory", value_parser = parse_dir)]
    pub universe: Option<PathBuf>,

    #[arg(long, help = "Event debug flag")]
    pub event_debug: bool,

    #[arg(long, help = "Force network flush", default_value_t = true)]
    pub force_network_flush: bool,

    #[arg(long, help = "The migrations to run", value_parser = parse_migrations)]
    pub migrations: Option<HashMap<String, PathBuf>>,

    #[arg(long, help = "Worlds to migrate", value_delimiter = ',')]
    pub migrate_worlds: Vec<String>,

    #[arg(long, help = "Runs command on boot. If multiple commands are provided they are executed synchronously in order.", value_delimiter = ',')]
    pub boot_command: Vec<String>,

    #[arg(long, help = "Allow self op command")]
    pub allow_op: bool,

    #[arg(long, help = "Authentication mode", default_value_t = AuthMode::Authenticated)]
    pub auth_mode: AuthMode,

    #[arg(long, help = "Session token for Session Service API")]
    pub session_token: Option<String>,

    #[arg(long, help = "Identity token (JWT)")]
    pub identity_token: Option<String>,
}

pub fn get() -> Arc<Options> {
    OPTIONS.get().unwrap().clone()
}

pub fn parse() {
    OPTIONS.set(Arc::new(Options::parse())).expect("Failed to parse options");
}

fn parse_dir(path: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(path);
    if !p.exists() {
        return Err(format!("Path '{}' does not exist", path));
    }
    if !p.is_dir() {
        return Err(format!("Path '{}' is not a directory", path));
    }
    Ok(p)
}

fn parse_dir_or_zip(path: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(path);
    if !p.exists() {
        return Err(format!("Path '{}' does not exist", path));
    }
    if !p.is_dir() && p.extension().map_or(true, |ext| ext != "zip") {
        return Err(format!("Path '{}' is not a directory or a .zip file", path));
    }
    Ok(p)
}

fn parse_migrations(s: &str) -> Result<HashMap<String, PathBuf>, String> {
    let mut map = HashMap::new();

    for pair in s.split(',') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next().ok_or_else(|| format!("Invalid migration entry: '{}'", pair))?;
        let value = kv.next().ok_or_else(|| format!("Invalid migration entry: '{}'", pair))?;

        if map.contains_key(key) {
            return Err(format!("String '{}' has already been specified!", key));
        }

        let path = PathBuf::from(value);
        if !path.exists() {
            return Err(format!("No file found for '{}'", value));
        }

        map.insert(key.to_string(), path);
    }

    Ok(map)
}

#[derive(Debug, Clone, ValueEnum)]
pub enum AuthMode {
    Authenticated,
    Offline,
    Insecure
}

impl std::fmt::Display for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMode::Authenticated => write!(f, "authenticated"),
            AuthMode::Offline => write!(f, "offline"),
            AuthMode::Insecure => write!(f, "insecure"),
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum TransportType {
    TCP,
    QUIC
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ValidationOption {
    Physics,
    Blocks,
    BlockStates,
    Entities,
    BlockFiller
}