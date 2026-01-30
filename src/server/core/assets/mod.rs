pub mod asset_module;
pub mod pack_loader;
pub mod asset_pack;
pub mod asset_registry;
pub mod asset_store;
pub mod asset_map;
mod types;
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

