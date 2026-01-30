/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.map;

import com.hypixel.fastutil.ints.Int2ObjectConcurrentHashMap;
import com.hypixel.hytale.assetstore.AssetExtraInfo;
import com.hypixel.hytale.assetstore.AssetMap;
import com.hypixel.hytale.assetstore.JsonAsset;
import com.hypixel.hytale.assetstore.codec.AssetCodec;
import com.hypixel.hytale.assetstore.map.CaseInsensitiveHashStrategy;
import it.unimi.dsi.fastutil.ints.IntIterator;
import it.unimi.dsi.fastutil.ints.IntSet;
import it.unimi.dsi.fastutil.ints.IntSets;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenCustomHashMap;
import it.unimi.dsi.fastutil.objects.ObjectOpenHashSet;
import it.unimi.dsi.fastutil.objects.ObjectSet;
import it.unimi.dsi.fastutil.objects.ObjectSets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.StampedLock;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DefaultAssetMap<K, T extends JsonAsset<K>>
extends AssetMap<K, T> {
    public static final AssetRef[] EMPTY_PAIR_ARRAY = new AssetRef[0];
    public static final String DEFAULT_PACK_KEY = "Hytale:Hytale";
    protected final StampedLock assetMapLock = new StampedLock();
    @Nonnull
    protected final Map<K, T> assetMap;
    protected final Map<K, AssetRef<T>[]> assetChainMap;
    protected final Map<String, ObjectSet<K>> packAssetKeys = new ConcurrentHashMap<String, ObjectSet<K>>();
    protected final Map<Path, ObjectSet<K>> pathToKeyMap = new ConcurrentHashMap<Path, ObjectSet<K>>();
    protected final Map<K, ObjectSet<K>> assetChildren;
    protected final Int2ObjectConcurrentHashMap<Set<K>> tagStorage = new Int2ObjectConcurrentHashMap();
    protected final Int2ObjectConcurrentHashMap<Set<K>> unmodifiableTagStorage = new Int2ObjectConcurrentHashMap();
    protected final IntSet unmodifiableTagKeys = IntSets.unmodifiable(this.tagStorage.keySet());

    public DefaultAssetMap() {
        this.assetMap = new Object2ObjectOpenCustomHashMap<K, T>(CaseInsensitiveHashStrategy.getInstance());
        this.assetChainMap = new Object2ObjectOpenCustomHashMap<K, AssetRef<T>[]>(CaseInsensitiveHashStrategy.getInstance());
        this.assetChildren = new Object2ObjectOpenCustomHashMap<K, ObjectSet<K>>(CaseInsensitiveHashStrategy.getInstance());
    }

    public DefaultAssetMap(@Nonnull Map<K, T> assetMap) {
        this.assetMap = assetMap;
        this.assetChainMap = new Object2ObjectOpenCustomHashMap<K, AssetRef<T>[]>(CaseInsensitiveHashStrategy.getInstance());
        this.assetChildren = new Object2ObjectOpenCustomHashMap<K, ObjectSet<K>>(CaseInsensitiveHashStrategy.getInstance());
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    @Nullable
    public T getAsset(K key) {
        long stamp = this.assetMapLock.tryOptimisticRead();
        JsonAsset value = (JsonAsset)this.assetMap.get(key);
        if (this.assetMapLock.validate(stamp)) {
            return (T)value;
        }
        stamp = this.assetMapLock.readLock();
        try {
            JsonAsset jsonAsset = (JsonAsset)this.assetMap.get(key);
            return (T)jsonAsset;
        }
        finally {
            this.assetMapLock.unlockRead(stamp);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    @Nullable
    public T getAsset(@Nonnull String packKey, K key) {
        long stamp = this.assetMapLock.tryOptimisticRead();
        T result = this.getAssetForPack0(packKey, key);
        if (this.assetMapLock.validate(stamp)) {
            return result;
        }
        stamp = this.assetMapLock.readLock();
        try {
            T t = this.getAssetForPack0(packKey, key);
            return t;
        }
        finally {
            this.assetMapLock.unlockRead(stamp);
        }
    }

    private T getAssetForPack0(@Nonnull String packKey, K key) {
        AssetRef<T>[] chain = this.assetChainMap.get(key);
        if (chain == null) {
            return null;
        }
        for (int i = 0; i < chain.length; ++i) {
            AssetRef<T> pair = chain[i];
            if (!Objects.equals(pair.pack, packKey)) continue;
            if (i == 0) {
                return null;
            }
            return (T)((JsonAsset)chain[i - 1].value);
        }
        return (T)((JsonAsset)this.assetMap.get(key));
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    @Nullable
    public Path getPath(K key) {
        long stamp = this.assetMapLock.tryOptimisticRead();
        Path result = this.getPath0(key);
        if (this.assetMapLock.validate(stamp)) {
            return result;
        }
        stamp = this.assetMapLock.readLock();
        try {
            Path path = this.getPath0(key);
            return path;
        }
        finally {
            this.assetMapLock.unlockRead(stamp);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    @Nullable
    public String getAssetPack(K key) {
        long stamp = this.assetMapLock.tryOptimisticRead();
        String result = this.getAssetPack0(key);
        if (this.assetMapLock.validate(stamp)) {
            return result;
        }
        stamp = this.assetMapLock.readLock();
        try {
            String string = this.getAssetPack0(key);
            return string;
        }
        finally {
            this.assetMapLock.unlockRead(stamp);
        }
    }

    @Nullable
    private Path getPath0(K key) {
        AssetRef<T> result = this.getAssetRef(key);
        return result != null ? result.path : null;
    }

    @Nullable
    private String getAssetPack0(K key) {
        AssetRef<T> result = this.getAssetRef(key);
        return result != null ? result.pack : null;
    }

    @Nullable
    private AssetRef<T> getAssetRef(K key) {
        AssetRef<T>[] chain = this.assetChainMap.get(key);
        if (chain == null) {
            return null;
        }
        return chain[chain.length - 1];
    }

    @Override
    public Set<K> getKeys(@Nonnull Path path) {
        ObjectSet<K> set = this.pathToKeyMap.get(path);
        return set == null ? ObjectSets.emptySet() : ObjectSets.unmodifiable(set);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    public Set<K> getChildren(K key) {
        ObjectSet result;
        long stamp = this.assetMapLock.tryOptimisticRead();
        ObjectSet<K> children = this.assetChildren.get(key);
        ObjectSet objectSet = result = children == null ? ObjectSets.emptySet() : ObjectSets.unmodifiable(children);
        if (this.assetMapLock.validate(stamp)) {
            return result;
        }
        stamp = this.assetMapLock.readLock();
        try {
            children = this.assetChildren.get(key);
            ObjectSet objectSet2 = children == null ? ObjectSets.emptySet() : ObjectSets.unmodifiable(children);
            return objectSet2;
        }
        finally {
            this.assetMapLock.unlockRead(stamp);
        }
    }

    @Override
    public int getAssetCount() {
        return this.assetMap.size();
    }

    @Override
    @Nonnull
    public Map<K, T> getAssetMap() {
        return Collections.unmodifiableMap(this.assetMap);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    @Nonnull
    public Map<K, Path> getPathMap(@Nonnull String packKey) {
        long stamp = this.assetMapLock.readLock();
        try {
            Map<Object, Path> map = this.assetChainMap.entrySet().stream().map(e -> Map.entry(e.getKey(), Arrays.stream((AssetRef[])e.getValue()).filter(v -> Objects.equals(v.pack, packKey)).findFirst())).filter(e -> ((Optional)e.getValue()).isPresent()).filter(e -> ((AssetRef)((Optional)e.getValue()).get()).path != null).collect(Collectors.toMap(Map.Entry::getKey, e -> ((AssetRef)((Optional)e.getValue()).get()).path));
            return map;
        }
        finally {
            this.assetMapLock.unlockRead(stamp);
        }
    }

    @Override
    public Set<K> getKeysForTag(int tagIndex) {
        return this.unmodifiableTagStorage.getOrDefault(tagIndex, ObjectSets.emptySet());
    }

    @Override
    @Nonnull
    public IntSet getTagIndexes() {
        return this.unmodifiableTagKeys;
    }

    @Override
    public int getTagCount() {
        return this.tagStorage.size();
    }

    @Override
    protected void clear() {
        long stamp = this.assetMapLock.writeLock();
        try {
            this.assetChildren.clear();
            this.assetChainMap.clear();
            this.pathToKeyMap.clear();
            this.assetMap.clear();
            this.tagStorage.clear();
            this.unmodifiableTagStorage.clear();
        }
        finally {
            this.assetMapLock.unlockWrite(stamp);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    protected void putAll(@Nonnull String packKey, @Nonnull AssetCodec<K, T> codec, @Nonnull Map<K, T> loadedAssets, @Nonnull Map<K, Path> loadedKeyToPathMap, @Nonnull Map<K, Set<K>> loadedAssetChildren) {
        long stamp = this.assetMapLock.writeLock();
        try {
            for (Map.Entry<K, Set<K>> entry : loadedAssetChildren.entrySet()) {
                this.assetChildren.computeIfAbsent(entry.getKey(), k -> new ObjectOpenHashSet(3)).addAll((Collection)entry.getValue());
            }
            for (Map.Entry<K, Iterable<Object>> entry : loadedKeyToPathMap.entrySet()) {
                this.pathToKeyMap.computeIfAbsent((Path)entry.getValue(), k -> new ObjectOpenHashSet(1)).add(entry.getKey());
            }
            for (Map.Entry<K, Iterable<Object>> entry : loadedAssets.entrySet()) {
                K key = entry.getKey();
                this.packAssetKeys.computeIfAbsent(packKey, v -> new ObjectOpenHashSet()).add(key);
                AssetRef<T>[] chain = this.assetChainMap.get(key);
                if (chain == null) {
                    chain = EMPTY_PAIR_ARRAY;
                }
                boolean found = false;
                for (AssetRef<T> pair : chain) {
                    if (!Objects.equals(pair.pack, packKey)) continue;
                    pair.value = entry.getValue();
                    found = true;
                    break;
                }
                if (!found) {
                    chain = Arrays.copyOf(chain, chain.length + 1);
                    chain[chain.length - 1] = new AssetRef<JsonAsset>(packKey, loadedKeyToPathMap.get(entry.getKey()), (JsonAsset)((Object)entry.getValue()));
                    this.assetChainMap.put(key, chain);
                }
                JsonAsset finalVal = (JsonAsset)chain[chain.length - 1].value;
                this.assetMap.put(key, finalVal);
            }
        }
        finally {
            this.assetMapLock.unlockWrite(stamp);
        }
        this.putAssetTags(codec, loadedAssets);
    }

    protected void putAssetTags(@Nonnull AssetCodec<K, T> codec, @Nonnull Map<K, T> loadedAssets) {
        for (Map.Entry<K, T> entry : loadedAssets.entrySet()) {
            AssetExtraInfo.Data data = codec.getData((JsonAsset)entry.getValue());
            if (data == null) continue;
            K key = entry.getKey();
            IntIterator iterator = data.getExpandedTagIndexes().iterator();
            while (iterator.hasNext()) {
                int tag = iterator.nextInt();
                this.putAssetTag(key, tag);
            }
        }
    }

    protected void putAssetTag(K key, int tag) {
        this.tagStorage.computeIfAbsent(tag, k -> {
            ObjectOpenHashSet set = new ObjectOpenHashSet(3);
            this.unmodifiableTagStorage.put(k, ObjectSets.unmodifiable(set));
            return set;
        }).add(key);
    }

    @Override
    public Set<K> getKeysForPack(@Nonnull String name) {
        return this.packAssetKeys.get(name);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    protected Set<K> remove(@Nonnull Set<K> keys) {
        long stamp = this.assetMapLock.writeLock();
        try {
            HashSet<K> children = new HashSet<K>();
            for (K key : keys) {
                AssetRef<T>[] chain = this.assetChainMap.remove(key);
                if (chain == null) continue;
                AssetRef<T> info = chain[chain.length - 1];
                if (info.path != null) {
                    this.pathToKeyMap.computeIfPresent(info.path, (p, list) -> {
                        list.remove(key);
                        if (list.isEmpty()) {
                            return null;
                        }
                        return list;
                    });
                }
                this.assetMap.remove(key);
                for (AssetRef<T> c : chain) {
                    this.packAssetKeys.get(Objects.requireNonNullElse(c.pack, DEFAULT_PACK_KEY)).remove(key);
                }
                for (ObjectSet objectSet : this.assetChildren.values()) {
                    objectSet.remove(key);
                }
                ObjectSet<K> child = this.assetChildren.remove(key);
                if (child == null) continue;
                children.addAll(child);
            }
            this.tagStorage.forEach((_k, value, removedKeys) -> value.removeAll((Collection<?>)removedKeys), keys);
            children.removeAll(keys);
            HashSet<K> hashSet = children;
            return hashSet;
        }
        finally {
            this.assetMapLock.unlockWrite(stamp);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    protected Set<K> remove(@Nonnull String packKey, @Nonnull Set<K> keys, @Nonnull List<Map.Entry<String, Object>> pathsToReload) {
        long stamp = this.assetMapLock.writeLock();
        try {
            HashSet<K> children = new HashSet<K>();
            ObjectSet<K> packKeys = this.packAssetKeys.get(Objects.requireNonNullElse(packKey, DEFAULT_PACK_KEY));
            if (packKeys == null) {
                Set set = Collections.emptySet();
                return set;
            }
            Iterator<K> iterator = keys.iterator();
            while (iterator.hasNext()) {
                Object key = iterator.next();
                packKeys.remove(key);
                AssetRef<T>[] chain = this.assetChainMap.remove(key);
                if (chain.length == 1) {
                    AssetRef<T> info = chain[0];
                    if (!Objects.equals(info.pack, packKey)) {
                        iterator.remove();
                        this.assetChainMap.put(key, chain);
                        continue;
                    }
                    if (info.path != null) {
                        this.pathToKeyMap.computeIfPresent(info.path, (p, list) -> {
                            list.remove(key);
                            if (list.isEmpty()) {
                                return null;
                            }
                            return list;
                        });
                    }
                    this.assetMap.remove(key);
                    for (ObjectSet<K> child : this.assetChildren.values()) {
                        child.remove(key);
                    }
                    ObjectSet<K> child = this.assetChildren.remove(key);
                    if (child == null) continue;
                    children.addAll(child);
                    continue;
                }
                iterator.remove();
                AssetRef[] newChain = new AssetRef[chain.length - 1];
                int offset = 0;
                for (int i = 0; i < chain.length; ++i) {
                    AssetRef<T> pair = chain[i];
                    if (Objects.equals(pair.pack, packKey)) {
                        if (pair.path == null) continue;
                        this.pathToKeyMap.computeIfPresent(pair.path, (p, list) -> {
                            list.remove(key);
                            if (list.isEmpty()) {
                                return null;
                            }
                            return list;
                        });
                        continue;
                    }
                    newChain[offset++] = pair;
                    if (pair.path != null) {
                        pathsToReload.add(Map.entry(pair.pack, pair.path));
                        continue;
                    }
                    pathsToReload.add(Map.entry(pair.pack, pair.value));
                }
                this.assetChainMap.put(key, newChain);
                AssetRef newAsset = newChain[newChain.length - 1];
                this.assetMap.put(key, (JsonAsset)newAsset.value);
                if (newAsset.path == null) continue;
                this.pathToKeyMap.computeIfAbsent(newAsset.path, k -> new ObjectOpenHashSet(1)).add(key);
            }
            this.tagStorage.forEach((_k, value, removedKeys) -> value.removeAll((Collection<?>)removedKeys), keys);
            children.removeAll(keys);
            HashSet<K> hashSet = children;
            return hashSet;
        }
        finally {
            this.assetMapLock.unlockWrite(stamp);
        }
    }

    protected static class AssetRef<T> {
        protected final String pack;
        protected final Path path;
        protected T value;

        protected AssetRef(String pack, Path path, T value) {
            this.pack = pack;
            this.path = path;
            this.value = value;
        }
    }
}

