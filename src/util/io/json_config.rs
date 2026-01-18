use std::fs;
use std::io::{Error, ErrorKind};
use std::path::Path;
use log::{error, info};
use serde::{Serialize};
use serde::de::DeserializeOwned;

pub struct JsonConfig;

/// Does not add missing fields on load (only until save is called)
impl JsonConfig {
    /// Load a config from a file
    pub fn load<T: DeserializeOwned + Serialize + Default>(path: &str, backup: bool) -> Option<T> {
        if !Path::new(path).exists() {
            let config = T::default();
            Self::save(path, &config, backup);
            return Some(config)
        }

        fn try_read<T: DeserializeOwned>(path: &str) -> Result<T, Error> {
            let s = fs::read_to_string(path)?;
            serde_json::from_str(&s).map_err(|e| Error::new(ErrorKind::InvalidData, e))
        }

        match try_read(path) {
            Ok(config) => return Some(config),
            Err(err) => {
                error!("Failed to load config file {}: {}", path, err);

                let backup_path = format!("{}.bak", path);
                if backup && Path::new(&backup_path).exists() {
                    error!("Trying to load config backup file {}", backup_path);
                    match try_read(&backup_path) {
                        Ok(config) => return Some(config),
                        Err(err) => error!("Failed to load config backup file {}: {}", backup_path, err)
                    }
                }
            }
        }

        None
    }

    /// Save a config to a file
    pub fn save<T: Serialize>(path: &str, config: &T, backup: bool) {
        if backup && Path::new(path).exists() {
            let backup_path = format!("{}.bak", path);
            if let Err(err) = fs::rename(path, &backup_path) {
                error!("Failed to save config backup file from {} to {}: {}", path, backup_path, err)
            }
        }

        match serde_json::to_string_pretty(config) {
            Err(err) => error!("Failed to serialize config file {}: {}", path, err),
            Ok(content) => {
                if let Err(err) = fs::write(path, content) {
                    error!("Failed to save config file {}: {}", path, err)
                }
            }
        }
    }
}