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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.StampedLock;
import javax.annotation.Nonnull;

public class IndexedAssetMap<K, T extends JsonAssetWithMap<K, IndexedAssetMap<K, T>>>
extends AssetMapWithIndexes<K, T> {
    private final AtomicInteger nextIndex = new AtomicInteger();
    private final StampedLock keyToIndexLock = new StampedLock();
    private final Object2IntMap<K> keyToIndex = new Object2IntOpenCustomHashMap(CaseInsensitiveHashStrategy.getInstance());

    public IndexedAssetMap() {
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

    public int getNextIndex() {
        return this.nextIndex.get();
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
                int index = this.keyToIndex.getInt(key);
                if (index == Integer.MIN_VALUE) {
                    index = this.nextIndex.getAndIncrement();
                    this.keyToIndex.put(key, index);
                }
                JsonAssetWithMap value = (JsonAssetWithMap)entry.getValue();
                this.putAssetTag(codec, key, index, value);
            }
        }
        finally {
            this.keyToIndexLock.unlockWrite(stamp);
        }
    }

    @Override
    protected Set<K> remove(@Nonnull Set<K> keys) {
        Set<K> remove = super.remove(keys);
        this.remove0(keys);
        return remove;
    }

    @Override
    protected Set<K> remove(@Nonnull String packKey, @Nonnull Set<K> keys, @Nonnull List<Map.Entry<String, Object>> pathsToReload) {
        Set<K> remove = super.remove(packKey, keys, pathsToReload);
        this.remove0(keys);
        return remove;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private void remove0(@Nonnull Set<K> keys) {
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
    }
}

