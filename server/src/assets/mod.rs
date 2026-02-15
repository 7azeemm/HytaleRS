pub mod asset_module;
pub mod asset_pack;
pub mod asset_reader;
pub mod asset_registry;
pub mod asset_store;
pub mod asset_type;
pub mod common;
pub mod errors;
pub mod structs;
pub mod types;
pub mod codec;
/*
# HytaleAssetStore extends AssetStore
- Packet Generator
- Notif Item Fn (to reload items on pack changes, not important rn)

# AssetStore
- Builder or instance is only created by HytaleAssetStore (can be merged probably)
- kClass is the key (usually String)
- tClass is the asset and extends JsonAssetWithMap<kClass, M extends AssetMap<kClass, tClass>>
- Codec: AssetCodec
- Map M (AssetMap<kClass, tClass>)
- Path/Extension (default ".json")
- KeyFn (Function to get asset's id)
- isUnknown (Only used by Interaction Asset, not so important)
- LoadsAfter: (Modifiable) Used for sorting on preloading assets and for injecting??
- LoadsBefore: (Not Modifiable) used once for sorting assets preloading with LoadsAfter
- replaceOnRemove: (Some assetMaps (M) requires this) used when removing/loading assets, simply
adds replacements for removed assets, and it's the only one responsible for generating Update/Remove packets
- preAddedAssets: (or preLoadedAssets) used for defaults
- childAssetsMap (Class Field): for storing child refs

## To Skip:
- GenerateAssetsEvent
- loadedContainedAssetsFor (Class Field)
- idProvider used once for generating schemas
- unmodifiable field
- References methods

## To look into:
- AssetMaps
- Pending Asset Stores

# BuilderCodec
- used to make codecs by:
- addField(): which adds BuilderField directly,
- append(): creates FieldBuilder, and then it calls .add() to add the field to the codec
 */