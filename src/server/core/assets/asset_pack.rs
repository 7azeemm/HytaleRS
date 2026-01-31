use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use ahash::{HashMap, HashSet, HashSetExt};
use log::{error, info};
use zip::ZipArchive;
use crate::plugin::plugin_manifest::PluginManifest;
use crate::server::core::assets::asset_reader::ZipReader;
use crate::server::core::assets::{AssetError, AssetResult};

pub struct AssetPack {
    name: String,
    path: PathBuf,
    reader: ZipReader,
    manifest: PluginManifest,
    immutable: bool,
}

impl AssetPack {
    pub async fn load_pack(path: &PathBuf) -> AssetResult<Self> {
        let start_time = Instant::now();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| "Pack file does not have a name".to_string())?;

        info!("Loading Asset Pack {}", file_name);

        let mut reader = ZipReader::open(path, file_name)?;

        let manifest = serde_json::from_str::<PluginManifest>(&reader.read_file("manifest.json")?)
            .map_err(|err| AssetError::IoError(format!("Failed to parse pack manifest: {}", err)))?;

        let immutable = file_name.ends_with(".zip") || file_name.ends_with(".jar");

        info!("Loaded Asset Pack {} in {:.2?}", manifest.name, start_time);

        Ok(Self {
            name: format!("{}:{}", manifest.group, manifest.name),
            path: path.clone(),
            reader,
            manifest,
            immutable
        })
    }

    pub async fn load_assets(&self) {
    }
}