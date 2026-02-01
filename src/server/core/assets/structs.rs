#[derive(Debug, Clone, Default)]
pub struct StoreStats {
    pub loaded: usize,
    pub failed: usize,
    pub invalid: usize,
    pub orphans: usize,
}

#[derive(Debug)]
pub struct RawAsset {
    pub key: String,
    pub path: String,
}