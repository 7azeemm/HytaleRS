/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.map;

import com.hypixel.hytale.assetstore.codec.AssetCodec;
import com.hypixel.hytale.assetstore.map.AssetMapWithIndexes;
import com.hypixel.hytale.assetstore.map.CaseInsensitiveHashStrategy;
import com.hypixel.hytale.assetstore.map.JsonAssetWithMap;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import it.unimi.dsi.fastutil.objects.Object2IntOpenCustomHashMap;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.StampedLock;
import java.util.function.ToIntBiFunction;
import javax.annotation.Nonnull;

public class ProvidedIndexAssetMap<K, T extends JsonAssetWithMap<K, ProvidedIndexAssetMap<K, T>>>
extends AssetMapWithIndexes<K, T> {
    private final StampedLock keyToIndexLock = new StampedLock();
    private final Object2IntMap<K> keyToIndex = new Object2IntOpenCustomHashMap(CaseInsensitiveHashStrategy.getInstance());
    private final ToIntBiFunction<K, T> indexGetter;

    public ProvidedIndexAssetMap(ToIntBiFunction<K, T> indexGetter) {
        this.indexGetter = indexGetter;
        this.keyToIndex.defaultReturnValue(Integer.MIN_VALUE);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public int getIndex(K key) {
        long stamp = this.keyToIndexLock.tryOptimisticRead();
        int value = this.keyToIndex.getInt(key);
        if (this.keyToIndexLock.validate(stamp)) {
            return value;
        }
        stamp = this.keyToIndexLock.readLock();
        try {
            int n = this.keyToIndex.getInt(key);
            return n;
        }
        finally {
            this.keyToIndexLock.unlockRead(stamp);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public int getIndexOrDefault(K key, int def) {
        long stamp = this.keyToIndexLock.tryOptimisticRead();
        int value = this.keyToIndex.getOrDefault((Object)key, def);
        if (this.keyToIndexLock.validate(stamp)) {
            return value;
        }
        stamp = this.keyToIndexLock.readLock();
        try {
            int n = this.keyToIndex.getOrDefault((Object)key, def);
            return n;
        }
        finally {
            this.keyToIndexLock.unlockRead(stamp);
        }
    }

    @Override
    protected void clear() {
        super.clear();
        long stamp = this.keyToIndexLock.writeLock();
        try {
            this.keyToIndex.clear();
        }
        finally {
            this.keyToIndexLock.unlockWrite(stamp);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    protected void putAll(@Nonnull String packKey, @Nonnull AssetCodec<K, T> codec, @Nonnull Map<K, T> loadedAssets, @Nonnull Map<K, Path> loadedKeyToPathMap, @Nonnull Map<K, Set<K>> loadedAssetChildren) {
        super.putAll(packKey, codec, loadedAssets, loadedKeyToPathMap, loadedAssetChildren);
        long stamp = this.keyToIndexLock.writeLock();
        try {
            for (Map.Entry<K, T> entry : loadedAssets.entrySet()) {
                K key = entry.getKey();
                JsonAssetWithMap value = (JsonAssetWithMap)entry.getValue();
                int index = this.keyToIndex.getInt(key);
                if (index == Integer.MIN_VALUE) {
                    index = this.indexGetter.applyAsInt(key, value);
                    this.keyToIndex.put(key, index);
                }
                this.putAssetTag(codec, key, index, value);
            }
        }
        finally {
            this.keyToIndexLock.unlockWrite(stamp);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    protected Set<K> remove(@Nonnull Set<K> keys) {
        Set<K> remove = super.remove(keys);
        long stamp = this.keyToIndexLock.writeLock();
        try {
            for (K key : keys) {
                int index = this.keyToIndex.removeInt(key);
                this.indexedTagStorage.forEachWithInt((_k, value, idx) -> value.remove(idx), index);
            }
        }
        finally {
            this.keyToIndexLock.unlockWrite(stamp);
        }
        return remove;
    }

    @Override
    public boolean requireReplaceOnRemove() {
        return false;
    }
}

