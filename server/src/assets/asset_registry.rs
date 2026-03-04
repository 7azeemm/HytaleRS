use crate::assets::asset_store::{AssetStore, StoreBase};
use crate::assets::asset_type::AssetType;
use crate::net::connection_manager::ConnectionContext;
use log::info;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;
use crate::assets::types::ambience_fx::AmbienceFX;
use crate::assets::types::audio_category::AudioCategory;
use crate::assets::types::block_breaking_decals::BlockBreakingDecal;
use crate::assets::types::block_hitbox::BlockHitBox;
use crate::assets::types::block_particle_set::BlockParticleSet;
use crate::assets::types::block_set::BlockSet;
use crate::assets::types::block_sound_set::BlockSoundSet;
use crate::assets::types::entity_stat_type::EntityStatType;
use crate::assets::types::entity_ui_component::EntityUIComponent;
use crate::assets::types::equalizer_effect::EqualizerEffect;
use crate::assets::types::fieldcraft_categories::FieldcraftCategories;
use crate::assets::types::fluid::Fluid;
use crate::assets::types::fluid_fx::FluidFX;
use crate::assets::types::hitbox_collision::HitboxCollisionConfig;
use crate::assets::types::item_animations::ItemAnimations;
use crate::assets::types::item_category::ItemCategory;
use crate::assets::types::item_quality::ItemQuality;
use crate::assets::types::item_reticle::ItemReticles;
use crate::assets::types::item_sound_set::ItemSoundSet;
use crate::assets::types::model_vfx::ModelVFX;
use crate::assets::types::particle_spawner::ParticleSpawner;
use crate::assets::types::particle_system::ParticleSystems;
use crate::assets::types::recipes::CraftingRecipes;
use crate::assets::types::repulsion::RepulsionConfig;
use crate::assets::types::resource_type::ResourceTypes;
use crate::assets::types::reverb_effect::ReverbEffect;
use crate::assets::types::sound_event::SoundEvent;
use crate::assets::types::sound_set::SoundSet;
use crate::assets::types::tag_pattern::TagPattern;
use crate::assets::types::trail::Trail;
use crate::assets::types::weather::Weather;

pub static STORE_REGISTRY: LazyLock<StoreRegistry> = LazyLock::new(|| StoreRegistry::new());

pub struct StoreRegistry {
    stores: RwLock<HashMap<TypeId, Arc<dyn StoreBase>>>,
}

impl StoreRegistry {
    pub fn new() -> Self {
        Self {
            stores: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register_stores(&self) {
        self.register::<BlockSet>().await;
        self.register::<BlockParticleSet>().await;
        self.register::<BlockHitBox>().await;
        self.register::<BlockSoundSet>().await;
        self.register::<BlockBreakingDecal>().await;
        self.register::<ItemSoundSet>().await;
        self.register::<AudioCategory>().await;
        self.register::<EqualizerEffect>().await;
        self.register::<ReverbEffect>().await;
        self.register::<SoundSet>().await;
        self.register::<SoundEvent>().await;
        self.register::<AmbienceFX>().await;
        self.register::<Weather>().await;
        self.register::<Fluid>().await;
        self.register::<FluidFX>().await;
        self.register::<ParticleSpawner>().await;
        self.register::<ModelVFX>().await;
        self.register::<RepulsionConfig>().await;
        self.register::<HitboxCollisionConfig>().await;
        self.register::<EntityUIComponent>().await;
        self.register::<EntityStatType>().await;
        self.register::<ItemReticles>().await;
        self.register::<ParticleSystems>().await;
        self.register::<ResourceTypes>().await;
        self.register::<FieldcraftCategories>().await;
        self.register::<TagPattern>().await;
        self.register::<CraftingRecipes>().await;
        self.register::<Trail>().await;
        self.register::<ItemCategory>().await;
        self.register::<ItemQuality>().await;
        self.register::<ItemAnimations>().await;
    }

    pub async fn register<T: AssetType + 'static>(&self) {
        let store = Arc::new(AssetStore::<T>::new());
        let name = store.name();
        self.stores.write().await.insert(store.type_id(), store);

        info!("Registered asset type: {} (path: {})", name, T::path());
    }

    pub async fn send_assets(&self, cx: &mut ConnectionContext) {
        for store in self.stores.read().await.values() {
            store.send_assets(cx).await;
        }
    }

    pub async fn get_all_stores(&self) -> Vec<Arc<dyn StoreBase>> {
        self.stores.read().await.values().cloned().collect()
    }

    pub async fn get<T: AssetType + 'static>(&self) -> Option<Arc<AssetStore<T>>> {
        self.stores
            .read()
            .await
            .get(&TypeId::of::<T>())
            .cloned()
            .and_then(|store| store.as_any_arc().downcast::<AssetStore<T>>().ok())
    }
}
