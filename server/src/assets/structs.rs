use log::info;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct StoreStats {
    pub loaded: usize,
    pub failed: usize,
    pub orphans: usize,
}

impl StoreStats {
    pub fn print(&self, name: &str) {
        info!(
            "{} Stats: Loaded: {}, Failed: {}, Orphans: {}",
            name,
            self.loaded,
            self.failed,
            self.orphans
        );
    }

    pub fn add(&mut self, other: &StoreStats) {
        self.loaded += other.loaded;
        self.failed += other.failed;
        self.orphans += other.orphans;
    }
}

pub struct PendingAsset {
    pub key: String,
    pub path: String,
}

pub struct ParsedAsset {
    pub key: String,
    pub path: String,
    pub parent: Option<String>,
    pub value: Value,
}

pub struct DecodedAsset<T> {
    pub key: String,
    pub asset: T,
}
