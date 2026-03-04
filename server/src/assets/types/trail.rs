use std::collections::HashMap;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::RawRwLock;
use serde::{Deserialize, Serialize};
use protocol::objects::objects::{Range, Vec2i};
use protocol::packets::assets::fx_render_mode::FXRenderMode;
use protocol::packets::assets::particle_spawner::IntersectionHighlight;
use protocol::packets::assets::trail::{Edge, TrailPacket, UpdateTrails};
use protocol::packets::assets::update_type::UpdateType;
use crate::assets::asset_type::{Asset, AssetType};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Trail {
    pub id: String,
    pub parent: Option<String>,
    pub texture: Option<String>,
    pub render_mode: FXRenderMode,
    pub intersection_highlight: IntersectionHighlight,
    pub life_span: i32,
    pub roll: f32,
    pub light_influence: f32,
    pub smooth: bool,
    pub start: Option<Edge>,
    pub end: Option<Edge>,
    pub animation: Animation
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Animation {
    pub frame_size: Option<Vec2i>,
    pub frame_range: Option<Range>,
    pub frame_life_span: i32,
}

impl AssetType for Trail {
    type InitPacketType = UpdateTrails;

    fn name() -> &'static str {
        "Trails"
    }

    fn path() -> &'static str {
        "Entity/Trails"
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
        let mut trails = HashMap::new();

        for (id, asset) in map.iter() {
            trails.insert(id.clone(), TrailPacket {
                life_span: 0,
                roll: 0.0,
                start: Default::default(),
                end: Default::default(),
                light_influence: 0.0,
                render_mode: Default::default(),
                intersection_highlight: Default::default(),
                smooth: false,
                frame_size: Default::default(),
                frame_range: Default::default(),
                frame_life_span: 0,
                id: Some(id.clone()),
                texture: None,
            });
            break;
        }

        UpdateTrails {
            update_type: UpdateType::Init,
            trails,
        }
    }
}
