use serde::{Deserialize, Serialize};
use protocol::objects::{Color, ColorAlpha};

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
    pub color: Color
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct TimeColorAlpha {
    pub hour: f32,
    pub color: ColorAlpha
}