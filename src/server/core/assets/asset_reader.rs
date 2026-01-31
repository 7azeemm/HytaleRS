use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};
use ahash::HashMap;
use log::info;
use zip::ZipArchive;
use crate::server::core::assets::{AssetError, AssetResult};

pub struct ZipReader {
    zip: ZipArchive<File>,
    file_cache: HashMap<String, usize>,  // path -> index in ZIP
}

impl ZipReader {
    pub fn open<P: AsRef<Path>>(path: P, file_name: &str) -> AssetResult<Self> {
        let start = Instant::now();

        let file = File::open(path.as_ref()).map_err(|e| AssetError::ZipError(e.to_string()))?;
        let mut zip = ZipArchive::new(file).map_err(|e| AssetError::ZipError(e.to_string()))?;

        info!("Opened Asset Pack {} in {:.2?}", file_name, start.elapsed());

        let start = Instant::now();

        // Build file cache
        let file_cache: HashMap<String, usize> = zip
            .file_names()
            .enumerate()
            .filter(|(_, name)| name.ends_with(".json") && !name.ends_with("/"))
            .map(|(i, name)| (name.to_string(), i))
            .collect();

        info!("Built file cache for {} in {:.2?}", file_name, start.elapsed());
        info!("Loaded {} json files from {}", file_cache.len(), file_name);

        Ok(ZipReader { zip, file_cache })
    }

    /// Get all JSON file paths
    pub fn list_json_files(&self) -> Vec<String> {
        self.file_cache.iter().map(|(path, _)| path.clone()).collect()
    }

    /// Read a file by path
    pub fn read_file(&mut self, path: &str) -> AssetResult<String> {
        if let Some(index) = self.file_cache.get(path) {
            let mut file = self.zip.by_index(*index).map_err(|e| AssetError::ZipError(e.to_string()))?;
            let mut content = String::new();
            file.read_to_string(&mut content).map_err(|e| AssetError::IoError(e.to_string()))?;
            return Ok(content);
        }

        Err(AssetError::NotFound(format!("File not found: {}", path)))
    }

    /// Read multiple files in parallel
    pub fn read_files_parallel(&mut self, paths: &[String]) -> Vec<(String, AssetResult<String>)> {
        paths.iter()
            .map(|path| (path.clone(), self.read_file(path)))
            .collect()
    }

    /// Total file count
    pub fn file_count(&self) -> usize {
        self.file_cache.len()
    }
}
