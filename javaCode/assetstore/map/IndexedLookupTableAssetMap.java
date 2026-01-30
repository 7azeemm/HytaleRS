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
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.StampedLock;
import java.util.function.IntFunction;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class IndexedLookupTableAssetMap<K, T extends JsonAssetWithMap<K, IndexedLookupTableAssetMap<K, T>>>
extends AssetMapWithIndexes<K, T> {
    private final AtomicInteger nextIndex = new AtomicInteger();
    private final StampedLock keyToIndexLock = new StampedLock();
    private final Object2IntMap<K> keyToIndex = new Object2IntOpenCustomHashMap(CaseInsensitiveHashStrategy.getInstance());
    @Nonnull
    private final IntFunction<T[]> arrayProvider;
    private final ReentrantLock arrayLock = new ReentrantLock();
    private T[] array;

    public IndexedLookupTableAssetMap(@Nonnull IntFunction<T[]> arrayProvider) {
        this.arrayProvider = arrayProvider;
        this.array = (JsonAssetWithMap[])arrayProvider.apply(0);
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
    @Nullable
    public T getAsset(int index) {
        if (index < 0 || index >= this.array.length) {
            return null;
        }
        return this.array[index];
    }

    public T getAssetOrDefault(int index, T def) {
        if (index < 0 || index >= this.array.length) {
            return def;
        }
        return this.array[index];
    }

    @Override
    protected void clear() {
        super.clear();
        long stamp = this.keyToIndexLock.writeLock();
        this.arrayLock.lock();
        try {
            this.keyToIndex.clear();
            this.array = (JsonAssetWithMap[])this.arrayProvider.apply(0);
        }
        finally {
            this.arrayLock.unlock();
            this.keyToIndexLock.unlockWrite(stamp);
        }
    }

    @Override
    protected void putAll(@Nonnull String packKey, @Nonnull AssetCodec<K, T> codec, @Nonnull Map<K, T> loadedAssets, @Nonnull Map<K, Path> loadedKeyToPathMap, @Nonnull Map<K, Set<K>> loadedAssetChildren) {
        super.putAll(packKey, codec, loadedAssets, loadedKeyToPathMap, loadedAssetChildren);
        this.putAll0(codec, loadedAssets);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private void putAll0(@Nonnull AssetCodec<K, T> codec, @Nonnull Map<K, T> loadedAssets) {
        long stamp = this.keyToIndexLock.writeLock();
        this.arrayLock.lock();
        try {
            int highestIndex = 0;
            for (K key : loadedAssets.keySet()) {
                int index = this.keyToIndex.getInt(key);
                if (index == Integer.MIN_VALUE) {
                    index = this.nextIndex.getAndIncrement();
                    this.keyToIndex.put(key, index);
                }
                if (index < 0) {
                    throw new IllegalArgumentException("Index can't be less than zero!");
                }
                if (index <= highestIndex) continue;
                highestIndex = index;
            }
            int length = highestIndex + 1;
            if (length < 0) {
                throw new IllegalArgumentException("Highest index can't be less than zero!");
            }
            if (length > this.array.length) {
                JsonAssetWithMap[] newArray = (JsonAssetWithMap[])this.arrayProvider.apply(length);
                System.arraycopy(this.array, 0, newArray, 0, this.array.length);
                this.array = newArray;
            }
            for (Map.Entry<K, T> entry : loadedAssets.entrySet()) {
                K key = entry.getKey();
                int index = this.keyToIndex.getInt(key);
                if (index < 0) {
                    throw new IllegalArgumentException("Index can't be less than zero!");
                }
                JsonAssetWithMap value = (JsonAssetWithMap)entry.getValue();
                this.array[index] = value;
                this.putAssetTag(codec, key, index, value);
            }
        }
        finally {
            this.arrayLock.unlock();
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
        this.arrayLock.lock();
        try {
            int i;
            for (K key : keys) {
                int blockId = this.keyToIndex.getInt(key);
                if (blockId == Integer.MIN_VALUE) continue;
                this.array[blockId] = null;
                this.indexedTagStorage.forEachWithInt((_k, value, id) -> value.remove(id), blockId);
            }
            for (i = this.array.length - 1; i > 0 && this.array[i] == null; --i) {
            }
            int length = i + 1;
            if (length != this.array.length) {
                JsonAssetWithMap[] newArray = (JsonAssetWithMap[])this.arrayProvider.apply(length);
                System.arraycopy(this.array, 0, newArray, 0, newArray.length);
                this.array = newArray;
            }
        }
        finally {
            this.arrayLock.unlock();
            this.keyToIndexLock.unlockWrite(stamp);
        }
    }
}

