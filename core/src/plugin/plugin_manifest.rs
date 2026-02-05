use ahash::HashMap;
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct PluginManifest {
    pub group: String,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub authors: Vec<AuthorInfo>,
    pub website: Option<String>,
    pub main: Option<String>,
    pub server_version: Option<String>,
    pub dependencies: HashMap<String, String>,
    pub optional_dependencies: HashMap<String, String>,
    pub load_before: HashMap<String, String>,
    pub disabled_by_default: bool,
    pub includes_asset_pack: bool
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthorInfo {
    pub name: Option<String>,
    pub email: Option<String>,
    pub url: Option<String>
}