use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct StoreStats {
    pub loaded: usize,
    pub failed: usize,
    pub orphans: usize,
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