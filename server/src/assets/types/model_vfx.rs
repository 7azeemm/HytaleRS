use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::io::codecs::FixedOption;
use protocol::objects::objects::{Color, Vec2f};
use protocol::packets::assets::model_vfx::{CurveType, EffectDirection, LoopOption, ModelVFXPacket, SwitchTo, UpdateModelVFXs};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ModelVFX {
    pub id: String,
    pub parent: Option<String>,
    pub switch_to: SwitchTo,
    pub effect_direction: EffectDirection,
    pub animation_duration: f32,
    // pub animation_range: Vec2f,
    pub loop_option: LoopOption,
    pub curve_type: CurveType,
    pub highlight_color: String,//Color
    pub highlight_thickness: f32,
    pub use_bloom_on_highlight: bool,
    pub use_progressive_highlight: bool,
    // pub noise_scale: Vec2f,
    // pub noise_scroll_speed: Option<Vec2f>,
    pub post_color: String,//Color
    pub post_color_opacity: f32,
}

impl Default for ModelVFX {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            parent: None,
            switch_to: SwitchTo::Disappear,
            effect_direction: EffectDirection::None,
            animation_duration: 0.0,
            // animation_range: Vec2f { x: 0.0, y: 1.0 },
            loop_option: LoopOption::PlayOnce,
            curve_type: CurveType::Linear,
            // highlight_color: Color { red: 255, green: 255, blue: 255 },
            highlight_color: "".to_string(),
            highlight_thickness: 0.0,
            use_bloom_on_highlight: false,
            use_progressive_highlight: false,
            // noise_scale: Vec2f { x: 50.0, y: 50.0 },
            // noise_scroll_speed: None,
            // post_color: Color { red: 255, green: 255, blue: 255 },
            post_color: "".to_string(),
            post_color_opacity: 1.0,
        }
    }
}

impl AssetType for ModelVFX {
    type InitPacketType = UpdateModelVFXs;

    fn name() -> &'static str {
        "ModelVFX"
    }

    fn path() -> &'static str {
        "Entity/ModelVFX"
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    fn generate_init_packet(map: RwLockReadGuard<RawRwLock, HashMap<String, Asset<Self>>>) -> Self::InitPacketType {
        let mut model_vfx = HashMap::new();

        for (i, (id, asset)) in map.iter().enumerate() {
            model_vfx.insert(i as i32, ModelVFXPacket {
                switch_to: asset.data.switch_to,
                effect_direction: asset.data.effect_direction,
                animation_duration: asset.data.animation_duration,
                // animation_range: FixedOption(asset.data.animation_range.clone().into()),
                animation_range: Default::default(),
                loop_option: asset.data.loop_option,
                curve_type: asset.data.curve_type,
                // highlight_color: FixedOption(asset.data.highlight_color.clone().into()),
                highlight_color: Default::default(),
                highlight_thickness: asset.data.highlight_thickness,
                use_bloom_on_highlight: asset.data.use_bloom_on_highlight,
                use_progressive_highlight: asset.data.use_progressive_highlight,
                // noise_scale: FixedOption(asset.data.noise_scale.clone().into()),
                // noise_scroll_speed: asset.data.noise_scroll_speed.clone().into(),
                // post_color: FixedOption(asset.data.post_color.clone().into()),
                noise_scale: Default::default(),
                noise_scroll_speed: Default::default(),
                post_color: Default::default(),
                post_color_opacity: asset.data.post_color_opacity,
                id: Some(id.clone()),
            });
        }

        UpdateModelVFXs {
            update_type: UpdateType::Init,
            max_id: map.len() as i32,
            model_vfx
        }
    }
}