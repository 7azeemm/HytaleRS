use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PluginIdentifier {
    pub group: String,
    pub name: String,
}

impl Serialize for PluginIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format!("{}:{}", self.group, self.name);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for PluginIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(serde::de::Error::custom(format!(
                "Invalid PluginIdentifier string: {s}"
            )));
        }
        Ok(PluginIdentifier {
            group: parts[0].to_string(),
            name: parts[1].to_string(),
        })
    }
}