/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.event;

import com.hypixel.hytale.assetstore.AssetExtraInfo;
import com.hypixel.hytale.assetstore.AssetMap;
import com.hypixel.hytale.assetstore.AssetRegistry;
import com.hypixel.hytale.assetstore.AssetStore;
import com.hypixel.hytale.assetstore.event.AssetsEvent;
import com.hypixel.hytale.assetstore.map.JsonAssetWithMap;
import com.hypixel.hytale.common.util.FormatUtil;
import com.hypixel.hytale.event.IProcessedEvent;
import com.hypixel.hytale.logger.HytaleLogger;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import javax.annotation.Nonnull;

public class GenerateAssetsEvent<K, T extends JsonAssetWithMap<K, M>, M extends AssetMap<K, T>>
extends AssetsEvent<K, T>
implements IProcessedEvent {
    private final Class<T> tClass;
    private final M assetMap;
    @Nonnull
    private final Map<K, T> loadedAssets;
    private final Map<K, Set<K>> assetChildren;
    @Nonnull
    private final Map<K, T> unmodifiableLoadedAssets;
    private final Map<K, T> addedAssets = new ConcurrentHashMap<K, T>();
    private final Map<K, Set<K>> addedAssetChildren = new ConcurrentHashMap<K, Set<K>>();
    private final Map<Class<? extends JsonAssetWithMap<?, ?>>, Map<?, Set<K>>> addedChildAssetsMap = new ConcurrentHashMap();
    private long before;

    public GenerateAssetsEvent(Class<T> tClass, M assetMap, @Nonnull Map<K, T> loadedAssets, Map<K, Set<K>> assetChildren) {
        this.tClass = tClass;
        this.assetMap = assetMap;
        this.loadedAssets = loadedAssets;
        this.assetChildren = assetChildren;
        this.unmodifiableLoadedAssets = Collections.unmodifiableMap(loadedAssets);
        this.before = System.nanoTime();
    }

    public Class<T> getAssetClass() {
        return this.tClass;
    }

    @Nonnull
    public Map<K, T> getLoadedAssets() {
        return this.unmodifiableLoadedAssets;
    }

    public M getAssetMap() {
        return this.assetMap;
    }

    public void addChildAsset(K childKey, T asset, @Nonnull K parent) {
        if (!this.loadedAssets.containsKey(parent) && ((AssetMap)this.assetMap).getAsset(parent) == null) {
            throw new IllegalArgumentException("Parent '" + String.valueOf(parent) + "' doesn't exist!");
        }
        if (parent.equals(childKey)) {
            throw new IllegalArgumentException("Unable to to add asset '" + String.valueOf(parent) + "' because it is its own parent!");
        }
        AssetStore assetStore = AssetRegistry.getAssetStore(this.tClass);
        AssetExtraInfo extraInfo = new AssetExtraInfo(assetStore.getCodec().getData(asset));
        assetStore.getCodec().validate(asset, extraInfo);
        extraInfo.getValidationResults().logOrThrowValidatorExceptions(assetStore.getLogger());
        this.addedAssets.put(childKey, asset);
        this.addedAssetChildren.computeIfAbsent(parent, k -> new HashSet()).add(childKey);
    }

    @SafeVarargs
    public final void addChildAsset(K childKey, T asset, K ... parents) {
        for (int i = 0; i < parents.length; ++i) {
            K parent = parents[i];
            if (!this.loadedAssets.containsKey(parent) && ((AssetMap)this.assetMap).getAsset(parent) == null) {
                throw new IllegalArgumentException("Parent at " + i + " '" + String.valueOf(parent) + "' doesn't exist!");
            }
            if (!parent.equals(childKey)) continue;
            throw new IllegalArgumentException("Unable to to add asset '" + String.valueOf(parent) + "' because it is its own parent!");
        }
        AssetStore assetStore = AssetRegistry.getAssetStore(this.tClass);
        AssetExtraInfo extraInfo = new AssetExtraInfo(assetStore.getCodec().getData(asset));
        assetStore.getCodec().validate(asset, extraInfo);
        extraInfo.getValidationResults().logOrThrowValidatorExceptions(assetStore.getLogger());
        this.addedAssets.put(childKey, asset);
        for (K parent : parents) {
            this.addedAssetChildren.computeIfAbsent(parent, k -> new HashSet()).add(childKey);
        }
    }

    public <P extends JsonAssetWithMap<PK, ?>, PK> void addChildAssetWithReference(K childKey, T asset, Class<P> parentAssetClass, @Nonnull PK parentKey) {
        Class<P> kc = parentAssetClass;
        if (((AssetMap)AssetRegistry.getAssetStore(kc).getAssetMap()).getAsset(parentKey) == null) {
            throw new IllegalArgumentException("Parent '" + String.valueOf(parentKey) + "' from " + String.valueOf(parentAssetClass) + " doesn't exist!");
        }
        if (parentKey.equals(childKey)) {
            throw new IllegalArgumentException("Unable to to add asset '" + String.valueOf(parentKey) + "' because it is its own parent!");
        }
        AssetStore assetStore = AssetRegistry.getAssetStore(this.tClass);
        AssetExtraInfo extraInfo = new AssetExtraInfo(assetStore.getCodec().getData(asset));
        assetStore.getCodec().validate(asset, extraInfo);
        extraInfo.getValidationResults().logOrThrowValidatorExceptions(assetStore.getLogger());
        this.addedAssets.put(childKey, asset);
        this.addedChildAssetsMap.computeIfAbsent(parentAssetClass, k -> new ConcurrentHashMap()).computeIfAbsent(parentKey, k -> new HashSet()).add(childKey);
    }

    public void addChildAssetWithReferences(K childKey, T asset, ParentReference<?, ?> ... parents) {
        for (int i = 0; i < parents.length; ++i) {
            ParentReference<?, ?> parent = parents[i];
            if (((AssetMap)AssetRegistry.getAssetStore(parent.getParentAssetClass()).getAssetMap()).getAsset(parent.getParentKey()) == null) {
                throw new IllegalArgumentException("Parent at " + i + " '" + String.valueOf(parent) + "' doesn't exist!");
            }
            if (!parent.parentKey.equals(childKey)) continue;
            throw new IllegalArgumentException("Unable to to add asset '" + String.valueOf(parent.parentKey) + "' because it is its own parent!");
        }
        AssetStore assetStore = AssetRegistry.getAssetStore(this.tClass);
        AssetExtraInfo extraInfo = new AssetExtraInfo(assetStore.getCodec().getData(asset));
        assetStore.getCodec().validate(asset, extraInfo);
        extraInfo.getValidationResults().logOrThrowValidatorExceptions(assetStore.getLogger());
        this.addedAssets.put(childKey, asset);
        for (ParentReference<?, ?> parent : parents) {
            this.addedChildAssetsMap.computeIfAbsent(parent.parentAssetClass, k -> new ConcurrentHashMap()).computeIfAbsent(parent.parentKey, k -> new HashSet()).add(childKey);
        }
    }

    @Override
    public void processEvent(@Nonnull String hookName) {
        HytaleLogger.getLogger().at(Level.INFO).log("Generated %d of %s from %s in %s", this.addedAssets.size(), this.tClass.getSimpleName(), hookName, FormatUtil.nanosToString(System.nanoTime() - this.before));
        this.loadedAssets.putAll(this.addedAssets);
        this.addedAssets.clear();
        for (Map.Entry<K, Set<K>> entry : this.addedAssetChildren.entrySet()) {
            K parent = entry.getKey();
            this.assetChildren.computeIfAbsent(parent, k -> ConcurrentHashMap.newKeySet()).addAll((Collection)entry.getValue());
        }
        this.addedAssetChildren.clear();
        for (Map.Entry<Object, Object> entry : this.addedChildAssetsMap.entrySet()) {
            Class k2 = (Class)entry.getKey();
            AssetStore assetStore = AssetRegistry.getAssetStore(k2);
            for (Map.Entry childEntry : ((Map)entry.getValue()).entrySet()) {
                assetStore.addChildAssetReferences(childEntry.getKey(), this.tClass, (Set)childEntry.getValue());
            }
        }
        this.addedChildAssetsMap.clear();
        this.before = System.nanoTime();
    }

    @Nonnull
    public String toString() {
        return "GenerateAssetsEvent{tClass=" + String.valueOf(this.tClass) + ", loadedAssets.size()=" + this.loadedAssets.size() + ", " + super.toString() + "}";
    }

    public static class ParentReference<P extends JsonAssetWithMap<PK, ?>, PK> {
        private final Class<P> parentAssetClass;
        private final PK parentKey;

        public ParentReference(Class<P> parentAssetClass, PK parentKey) {
            this.parentAssetClass = parentAssetClass;
            this.parentKey = parentKey;
        }

        public Class<P> getParentAssetClass() {
            return this.parentAssetClass;
        }

        public PK getParentKey() {
            return this.parentKey;
        }

        @Nonnull
        public String toString() {
            return "ParentReference{parentAssetClass=" + String.valueOf(this.parentAssetClass) + ", parentKey=" + String.valueOf(this.parentKey) + "}";
        }
    }
}

