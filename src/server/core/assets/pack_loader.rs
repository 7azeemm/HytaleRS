use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use ahash::{HashMap, HashSet, HashSetExt};
use log::{error, info};
use zip::ZipArchive;
use crate::plugin::plugin_manifest::PluginManifest;
use crate::server::core::assets::asset_pack::{AssetPack, AssetRoot, DirRoot, ZipIndex, ZipRoot};

pub async fn load_pack(path: &PathBuf) -> Option<AssetPack> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    let manifest = match load_pack_manifest(path, &name) {
        Ok(manifest) => manifest,
        Err(err) => {
            error!("Skipping pack {}: {}", name, err);
            return None;
        }
    };

    let is_zip = name.ends_with(".zip") || name.ends_with(".jar");

    let (root, is_immutable): (Box<dyn AssetRoot>, bool) = if is_zip {
        let index = match build_zip_index(&path) {
            Ok(index) => index,
            Err(err) => {
                error!("Failed to build zip index: {err}");
                return None
            }
        };
        (Box::new(ZipRoot::new(Arc::new(index))), true)
    } else {
        let immutable = path.join("CommonAssetsIndex.hashes").is_file();
        (Box::new(DirRoot::new(path.clone())), immutable)
    };

    Some(AssetPack {
        name,
        root,
        is_immutable,
        manifest,
    })
}

fn load_pack_manifest<P: AsRef<Path>>(pack_path: P, file_name: &str) -> Result<PluginManifest, Box<dyn Error>> {
    let pack_path = pack_path.as_ref();

    // Handle .zip files
    if file_name.ends_with(".zip") {
        return match load_manifest_from_zip(pack_path) {
            Ok(Some(manifest)) => Ok(manifest),
            Ok(None) => Err("Missing manifest.json".into()),
            Err(e) => Err(e),
        }
    }

    // Handle directories
    if pack_path.is_dir() {
        let manifest_path = pack_path.join("manifest.json");
        if manifest_path.exists() {
            return load_manifest_from_file(&manifest_path);
        }
    }

    Err("Missing manifest.json".into())
}

fn load_manifest_from_zip<P: AsRef<Path>>(zip_path: P) -> Result<Option<PluginManifest>, Box<dyn Error>> {
    let zip_path = zip_path.as_ref();
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;

    match archive.by_name("manifest.json") {
        Ok(mut manifest_file) => {
            let mut contents = String::new();
            manifest_file.read_to_string(&mut contents)?;
            let manifest: PluginManifest = serde_json::from_str(&contents)?;
            Ok(Some(manifest))
        }
        Err(_) => Ok(None),
    }
}

fn load_manifest_from_file<P: AsRef<Path>>(manifest_path: P) -> Result<PluginManifest, Box<dyn Error>> {
    let manifest_path = manifest_path.as_ref();

    let file = File::open(manifest_path)?;
    let reader = BufReader::new(file);
    let manifest: PluginManifest = serde_json::from_reader(reader)?;

    Ok(manifest)
}

pub fn build_zip_index(path: &Path) -> Result<ZipIndex, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(file)?;

    let mut files = HashSet::with_capacity(zip.len());
    let mut dirs: HashMap<String, Vec<String>> = HashMap::default();

    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        let name = entry.name().to_string();

        if entry.is_dir() {
            // Track directory
            dirs.entry(name.clone()).or_default();
        } else {
            files.insert(name.clone());

            // Track parent directories and add file as child
            let normalized = name.trim_start_matches('/');
            if let Some(parent_pos) = normalized.rfind('/') {
                let parent_dir = format!("{}/", &normalized[..parent_pos + 1]);
                let file_name = normalized[parent_pos + 1..].to_string();
                dirs.entry(parent_dir).or_default().push(file_name);
            }
        }
    }

    Ok(ZipIndex {
        zip_path: path.to_path_buf(),
        files,
        dirs,
    })
}