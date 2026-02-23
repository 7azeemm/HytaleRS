use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct TimeFloat {
    pub hour: f32,
    pub value: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct TimeColor {
    pub hour: f32,
    pub color: String//FIXME: `Color` with custom deserializer
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct TimeColorAlpha {
    pub hour: f32,
    pub color: String//FIXME: `ColorAlpha` with custom deserializer
}