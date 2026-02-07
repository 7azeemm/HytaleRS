use crate::assets::errors::{AssetError, AssetResult};
use ahash::HashMap;
use log::info;
use parking_lot::Mutex;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};
use zip::ZipArchive;

pub struct ZipReader {
    zip: Mutex<ZipArchive<File>>,
    file_cache: HashMap<String, usize>, // path -> index in ZIP
}

impl ZipReader {
    pub fn open<P: AsRef<Path>>(path: P, file_name: &str) -> AssetResult<Self> {
        let file = File::open(path.as_ref()).map_err(|e| AssetError::ZipError(e.to_string()))?;
        let mut zip = ZipArchive::new(file).map_err(|e| AssetError::ZipError(e.to_string()))?;

        // Build file cache
        let file_cache: HashMap<String, usize> = zip
            .file_names()
            .enumerate()
            .filter(|(_, name)| !name.ends_with("/"))
            .map(|(i, name)| (name.to_string(), i))
            .collect();

        info!("Loaded {} files from {}", file_cache.len(), file_name);

        Ok(ZipReader {
            zip: Mutex::new(zip),
            file_cache,
        })
    }

    pub fn iter(&self, path: &str, extension: &str) -> impl Iterator<Item = &String> {
        self.file_cache
            .keys()
            .filter(move |file| file.starts_with(path) && file.ends_with(extension))
    }

    pub fn read_file(&self, path: &str) -> AssetResult<Vec<u8>> {
        if let Some(index) = self.file_cache.get(path) {
            let mut zip = self.zip.lock();
            let mut file = zip
                .by_index(*index)
                .map_err(|e| AssetError::ZipError(e.to_string()))?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)
                .map_err(|e| AssetError::IoError(e.to_string()))?;
            return Ok(content);
        }

        Err(AssetError::NotFound(format!("File not found: {}", path)))
    }
}
