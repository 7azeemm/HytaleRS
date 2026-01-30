use crate::plugin::plugin_manifest::PluginManifest;
use std::io;

pub struct AssetPack {
    pub name: String,
    pub root: Box<dyn AssetRoot>,
    pub is_immutable: bool,
    pub manifest: PluginManifest,
}

impl std::fmt::Debug for AssetPack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssetPack")
            .field("name", &self.name)
            .field("root", &format!("Box<dyn AssetRoot>({})", self.root.kind()))
            .field("is_immutable", &self.is_immutable)
            .field("manifest", &self.manifest)
            .finish()
    }
}

/// Virtual path that can represent either a filesystem directory or a zip archive entry
#[derive(Debug, Clone)]
pub enum VirtualPath {
    Directory(PathBuf),
    Zip { zip: Arc<ZipIndex>, prefix: String },
}

impl VirtualPath {
    /// Check if this path points to a directory
    pub fn is_dir(&self) -> bool {
        match self {
            VirtualPath::Directory(path) => path.is_dir(),
            VirtualPath::Zip { zip, prefix } => {
                let dir_key = format!("{}/", prefix.trim_end_matches('/'));
                zip.dirs.contains_key(&dir_key)
            }
        }
    }

    /// Check if this path exists
    pub fn exists(&self) -> bool {
        match self {
            VirtualPath::Directory(path) => path.exists(),
            VirtualPath::Zip { zip, prefix } => {
                let normalized = prefix.trim_start_matches('/');
                zip.files.contains(normalized) || zip.dirs.contains_key(&format!("{}/", normalized))
            }
        }
    }

    /// Read the file contents at this path
    pub fn read(&self) -> io::Result<Vec<u8>> {
        match self {
            VirtualPath::Directory(path) => fs::read(path),
            VirtualPath::Zip { zip, prefix } => {
                let file = File::open(&zip.zip_path)?;
                let mut archive = ZipArchive::new(file)?;
                let mut entry = archive.by_name(prefix.trim_start_matches('/'))?;
                let mut buf = Vec::with_capacity(entry.size() as usize);
                entry.read_to_end(&mut buf)?;
                Ok(buf)
            }
        }
    }

    /// Join this path with another component
    pub fn join(&self, path: &str) -> VirtualPath {
        match self {
            VirtualPath::Directory(dir) => VirtualPath::Directory(dir.join(path)),
            VirtualPath::Zip { zip, prefix } => {
                let new_prefix = format!("{}/{}", prefix.trim_end_matches('/'), path);
                VirtualPath::Zip {
                    zip: zip.clone(),
                    prefix: new_prefix,
                }
            }
        }
    }
}

/// Debug formatter for VirtualPath
pub fn debug_virtual(path: &VirtualPath) -> String {
    match path {
        VirtualPath::Directory(p) => format!("dir:{}", p.display()),
        VirtualPath::Zip { zip, prefix } => {
            format!("zip:{}!{}", zip.zip_path.display(), prefix)
        }
    }
}

pub trait AssetRoot: Send + Sync {
    /// For logging / debugging
    fn kind(&self) -> &'static str;

    /// Fast existence check
    fn exists(&self, path: &str) -> bool;

    /// Is directory?
    fn is_dir(&self, path: &str) -> bool;

    /// List direct children
    fn list_dir(&self, path: &str) -> Vec<String>;

    /// Read full file (you can later add streaming)
    fn read(&self, path: &str) -> std::io::Result<Vec<u8>>;

    /// Resolve a path within this root and return a VirtualPath
    fn resolve(&self, path: &str) -> VirtualPath;
}

use ahash::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use zip::ZipArchive;

pub struct DirRoot {
    base: PathBuf,
}

impl DirRoot {
    pub fn new(base: PathBuf) -> Self {
        Self { base }
    }

    #[inline]
    fn resolve_path(&self, path: &str) -> PathBuf {
        self.base.join(path)
    }
}

impl AssetRoot for DirRoot {
    fn kind(&self) -> &'static str {
        "directory"
    }

    fn exists(&self, path: &str) -> bool {
        self.resolve_path(path).exists()
    }

    fn is_dir(&self, path: &str) -> bool {
        self.resolve_path(path).is_dir()
    }

    fn list_dir(&self, path: &str) -> Vec<String> {
        let dir = self.resolve_path(path);
        let Ok(read) = fs::read_dir(dir) else {
            return vec![];
        };

        read.filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect()
    }

    fn read(&self, path: &str) -> std::io::Result<Vec<u8>> {
        fs::read(self.resolve_path(path))
    }

    fn resolve(&self, path: &str) -> VirtualPath {
        VirtualPath::Directory(self.resolve_path(path))
    }
}

#[derive(Debug)]
pub struct ZipIndex {
    pub zip_path: PathBuf,
    pub files: HashSet<String>,             // full paths
    pub dirs: HashMap<String, Vec<String>>, // prefix → children
}

pub struct ZipRoot {
    index: Arc<ZipIndex>,
}

impl ZipRoot {
    pub fn new(index: Arc<ZipIndex>) -> Self {
        Self { index }
    }

    #[inline]
    fn normalize(p: &str) -> String {
        p.trim_start_matches('/').to_string()
    }
}

impl AssetRoot for ZipRoot {
    fn kind(&self) -> &'static str {
        "zip"
    }

    fn exists(&self, path: &str) -> bool {
        let p = Self::normalize(path);
        self.index.files.contains(&p) || self.index.dirs.contains_key(&format!("{}/", p))
    }

    fn is_dir(&self, path: &str) -> bool {
        let p = format!("{}/", Self::normalize(path));
        self.index.dirs.contains_key(&p)
    }

    fn list_dir(&self, path: &str) -> Vec<String> {
        let p = format!("{}/", Self::normalize(path));
        self.index.dirs.get(&p).cloned().unwrap_or_default()
    }

    fn read(&self, path: &str) -> std::io::Result<Vec<u8>> {
        let p = Self::normalize(path);

        let file = File::open(&self.index.zip_path)?;
        let mut zip = ZipArchive::new(file)?;
        let mut f = zip.by_name(&p)?;

        let mut buf = Vec::with_capacity(f.size() as usize);
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn resolve(&self, path: &str) -> VirtualPath {
        VirtualPath::Zip {
            zip: self.index.clone(),
            prefix: Self::normalize(path),
        }
    }
}
