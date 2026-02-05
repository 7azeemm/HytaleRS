use std::fmt;

#[derive(Debug, Clone)]
pub enum AssetError {
    Error(String),
    NotFound(String),
    JsonError(String),
    DeserializeError(String),
    ValidationError(String),
    IoError(String),
    AlreadyExists(String),
    ParentNotFound(String),
    CircularReference(String),
    TypeNotRegistered(String),
    TypeError(String),
    CrossStoreRefFailed(String),
    ZipError(String),
}

impl fmt::Display for AssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetError::Error(id) => write!(f, "Asset error: {}", id),
            AssetError::NotFound(id) => write!(f, "Asset not found: {}", id),
            AssetError::JsonError(e) => write!(f, "JSON error: {}", e),
            AssetError::DeserializeError(e) => write!(f, "Deserialize error: {}", e),
            AssetError::ValidationError(e) => write!(f, "Validation error: {}", e),
            AssetError::IoError(e) => write!(f, "IO error: {}", e),
            AssetError::AlreadyExists(id) => write!(f, "Asset already exists: {}", id),
            AssetError::ParentNotFound(id) => write!(f, "Parent not found: {}", id),
            AssetError::CircularReference(chain) => write!(f, "Circular reference: {}", chain),
            AssetError::TypeNotRegistered(t) => write!(f, "Type not registered: {}", t),
            AssetError::TypeError(e) => write!(f, "Type error: {}", e),
            AssetError::CrossStoreRefFailed(e) => write!(f, "Cross-store reference failed: {}", e),
            AssetError::ZipError(e) => write!(f, "ZIP error: {}", e),
        }
    }
}

impl std::error::Error for AssetError {}

impl From<String> for AssetError {
    fn from(value: String) -> Self {
        AssetError::Error(value)
    }
}

pub type AssetResult<T> = Result<T, AssetError>;

/*
1. Register assets (AssetRegistryLoader)
2. Setup Asset Module
    1. Loads assets.zip
    2. Register for LoadAssetEvent (priority -16):
        1. Gets registered assets
        2. Sort them (some require others to load before)
        3. Load pre added assets (loading the asset store) (from registers not the pack)
        4. Load assets
    3. Register for AssetPackRegisterEvent (-16): loads the assets again
    4. Register for AssetPackUnregisterEvent
    5. Register for LoadAssetEvent: validates world gen
    6. Register for RegisterAssetStoreEvent: add to pending asset stores (for plugins restart ig)
    7. Register for RemoveAssetStoreEvent: not important
    8. Register for BootEvent (just logging): not important
3. Setup Common Asset Module
    1. Register for SendCommonAssetsEvent: used to send common assets to the player
    2. Register for LoadAssetEvent (-32): loads the common assets
    3. Register for AssetPackRegisterEvent (-32): loads the common assets again
    4. Register for AssetPackUnregisterEvent
4. Setup Cosmetics Module (not important now)

Events:
1. AssetPackRegisterEvent:
- Called on plugins setup restart?
- Not on first setup call bc if 'hasLoaded' is true, calls it

Missing stuff:
- AssetPackRegisterEvent: loads the packs after plugins restart
- AssetPackUnregisterEvent
- RegisterAssetStoreEvent
- RemoveAssetStoreEvent

*/
