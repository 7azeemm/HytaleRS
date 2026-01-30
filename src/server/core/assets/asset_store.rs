use crate::server::core::assets::asset_map::AssetMap;
use crate::server::core::assets::asset_pack::{AssetPack, VirtualPath};
use ahash::{HashSet, HashSetExt};
use log::{error, info};
use serde::de::DeserializeOwned;
use std::any::TypeId;
use std::error::Error;
use std::fmt::Debug;

pub trait AssetStore: Send + Sync + Debug {
    fn type_id(&self) -> TypeId;
    fn type_name(&self) -> &'static str;

    fn name(&self) -> &str;
    fn path(&self) -> &str;
    fn extension(&self) -> &str;

    fn dependencies(&self) -> &[String];

    fn load_from_directory(&self, pack_name: &str, root: &VirtualPath) -> AssetLoadResult;

    fn is_unmodifiable(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct TypedAssetStore<T: Send + Sync + Debug + DeserializeOwned + 'static> {
    name: String,
    path: String,
    extension: String,
    dependencies: Vec<String>,
    map: AssetMap<T>,
}

impl<T: Send + Sync + Debug + DeserializeOwned + 'static> TypedAssetStore<T> {
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        extension: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            extension: extension.into(),
            dependencies: Vec::new(),
            map: AssetMap::new(),
        }
    }

    pub fn asset_map(&self) -> &AssetMap<T> {
        &self.map
    }

    /// Load assets from paths and insert them into the map
    fn load_assets_from_paths(&self, pack_key: &str, paths: Vec<VirtualPath>) -> AssetLoadResult {
        let mut loaded = 0;
        let mut failed = 0;

        for path in paths {
            match self.load_single_asset(&path) {
                Ok((key, asset)) => {
                    self.map.insert(&key, asset, pack_key);
                    loaded += 1;
                }
                Err(e) => {
                    error!("Failed to load asset from {:?}: {}", path, e);
                    failed += 1;
                }
            }
        }

        AssetLoadResult { loaded, failed }
    }

    /// Load a single asset from a VirtualPath
    fn load_single_asset(&self, path: &VirtualPath) -> Result<(String, T), Box<dyn Error>> {
        let bytes = path.read()?;
        let asset: T = serde_json::from_slice(&bytes)?;
        let key = self.extract_key_from_path(path);
        Ok((key, asset))
    }

    /// Extract the asset key from the file path
    /// e.g., "Server/Item/Block/Sets/stone.json" -> "stone"
    fn extract_key_from_path(&self, path: &VirtualPath) -> String {
        let full_path = match path {
            VirtualPath::Directory(p) => p.to_string_lossy().to_string(),
            VirtualPath::Zip { prefix, .. } => prefix.clone(),
        };

        // Remove the store path prefix and extension
        let store_path = self.path();
        let extension = self.extension();

        // Find the last occurrence of the store path
        if let Some(pos) = full_path.find(store_path) {
            let after_store = &full_path[pos + store_path.len()..];
            // Remove leading slash and extension
            let without_leading = after_store.trim_start_matches('/').trim_start_matches('\\');
            let without_ext = if without_leading.ends_with(extension) {
                &without_leading[..without_leading.len() - extension.len()]
            } else {
                without_leading
            };
            without_ext.to_string()
        } else {
            // Fallback: just use the filename without extension
            full_path
                .split(&['/', '\\'])
                .last()
                .map(|s| {
                    if s.ends_with(extension) {
                        s[..s.len() - extension.len()].to_string()
                    } else {
                        s.to_string()
                    }
                })
                .unwrap_or_else(|| full_path.clone())
        }
    }
}

impl<T: Send + Sync + Debug + DeserializeOwned + 'static> AssetStore for TypedAssetStore<T> {
    fn type_id(&self) -> TypeId {
        TypeId::of::<T>()
    }

    fn type_name(&self) -> &'static str {
        std::any::type_name::<T>()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn extension(&self) -> &str {
        &self.extension
    }

    fn dependencies(&self) -> &[String] {
        &self.dependencies
    }

    fn load_from_directory(&self, pack_name: &str, path: &VirtualPath) -> AssetLoadResult {
        let mut files = Vec::new();

        match path {
            VirtualPath::Directory(dir) => {
                for entry in walkdir::WalkDir::new(dir)
                    .into_iter()
                    .filter_map(Result::ok)
                {
                    if entry.file_type().is_file()
                        && entry.path().to_string_lossy().ends_with(self.extension())
                    {
                        files.push(VirtualPath::Directory(entry.path().to_path_buf()));
                    }
                }
            }

            VirtualPath::Zip { zip, prefix } => {
                for name in zip.files.iter() {
                    if name.starts_with(prefix) && name.ends_with(self.extension()) {
                        files.push(VirtualPath::Zip {
                            zip: zip.clone(),
                            prefix: name.clone(),
                        });
                    }
                }
            }
        }

        self.load_assets_from_paths(pack_name, files)
    }
}

pub struct AssetLoadResult {
    pub loaded: usize,
    pub failed: usize,
}

pub struct RawAsset {
    pub key: String,
    pub path: VirtualPath,
}
