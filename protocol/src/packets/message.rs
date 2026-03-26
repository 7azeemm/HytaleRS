use std::collections::HashMap;
use macros::{packet_enum, packet_field};
use crate::packets::param_value::ParamValue;

#[packet_field]
pub struct FormattedMessage {
    pub bold: MaybeBool,
    pub italic: MaybeBool,
    pub monospace: MaybeBool,
    pub underlined: MaybeBool,
    pub markup_enabled: bool,
    pub raw_text: Option<String>,
    pub message_id: Option<String>,
    pub children: Vec<FormattedMessage>,
    pub params: HashMap<String, ParamValue>,
    pub message_params: HashMap<String, FormattedMessage>,
    pub color: Option<String>,
    pub link: Option<String>,
    pub image: Option<FormattedMessageImage>
}

#[packet_enum]
pub enum MaybeBool {
    Null,
    False,
    True
}

#[packet_field]
pub struct FormattedMessageImage {
    pub width: i32,
    pub height: i32,
    pub file_path: String
}

impl FormattedMessage {
    pub fn new(message: &str) -> Self {
        Self {
            bold: MaybeBool::Null,
            italic: MaybeBool::Null,
            monospace: MaybeBool::Null,
            underlined: MaybeBool::Null,
            markup_enabled: false,
            raw_text: None,
            message_id: Some(message.to_owned()),
            children: vec![],
            params: Default::default(),
            message_params: Default::default(),
            color: None,
            link: None,
            image: None,
        }
    }
}