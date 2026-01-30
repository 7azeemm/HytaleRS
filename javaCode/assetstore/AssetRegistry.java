/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore;

import com.hypixel.hytale.assetstore.AssetMap;
import com.hypixel.hytale.assetstore.AssetStore;
import com.hypixel.hytale.assetstore.event.RegisterAssetStoreEvent;
import com.hypixel.hytale.assetstore.event.RemoveAssetStoreEvent;
import com.hypixel.hytale.assetstore.map.JsonAssetWithMap;
import com.hypixel.hytale.event.IEventDispatcher;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import it.unimi.dsi.fastutil.objects.Object2IntOpenHashMap;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.locks.StampedLock;
import javax.annotation.Nonnull;

public class AssetRegistry {
    public static final ReadWriteLock ASSET_LOCK = new ReentrantReadWriteLock();
    public static boolean HAS_INIT = false;
    public static final int TAG_NOT_FOUND = Integer.MIN_VALUE;
    private static final Map<Class<? extends JsonAssetWithMap>, AssetStore<?, ?, ?>> storeMap = new HashMap();
    private static final Map<Class<? extends JsonAssetWithMap>, AssetStore<?, ?, ?>> storeMapUnmodifiable = Collections.unmodifiableMap(storeMap);
    private static final AtomicInteger NEXT_TAG_INDEX = new AtomicInteger();
    private static final StampedLock TAG_LOCK = new StampedLock();
    private static final Object2IntMap<String> TAG_MAP = new Object2IntOpenHashMap<String>();
    private static final Object2IntMap<String> CLIENT_TAG_MAP = new Object2IntOpenHashMap<String>();

    @Nonnull
    public static Map<Class<? extends JsonAssetWithMap>, AssetStore<?, ?, ?>> getStoreMap() {
        return storeMapUnmodifiable;
    }

    public static <K, T extends JsonAssetWithMap<K, M>, M extends AssetMap<K, T>> AssetStore<K, T, M> getAssetStore(Class<T> tClass) {
        return storeMap.get(tClass);
    }

    @Nonnull
    public static <K, T extends JsonAssetWithMap<K, M>, M extends AssetMap<K, T>, S extends AssetStore<K, T, M>> S register(@Nonnull S assetStore) {
        ASSET_LOCK.writeLock().lock();
        try {
            if (storeMap.putIfAbsent(assetStore.getAssetClass(), assetStore) != null) {
                throw new IllegalArgumentException("Asset Store already exists for " + String.valueOf(assetStore.getAssetClass()));
            }
        }
        finally {
            ASSET_LOCK.writeLock().unlock();
        }
        IEventDispatcher<RegisterAssetStoreEvent, RegisterAssetStoreEvent> dispatch = assetStore.getEventBus().dispatchFor(RegisterAssetStoreEvent.class);
        if (dispatch.hasListener()) {
            dispatch.dispatch(new RegisterAssetStoreEvent(assetStore));
        }
        return assetStore;
    }

    public static <K, T extends JsonAssetWithMap<K, M>, M extends AssetMap<K, T>, S extends AssetStore<K, T, M>> void unregister(@Nonnull S assetStore) {
        ASSET_LOCK.writeLock().lock();
        try {
            storeMap.remove(assetStore.getAssetClass());
        }
        finally {
            ASSET_LOCK.writeLock().unlock();
        }
        IEventDispatcher<RemoveAssetStoreEvent, RemoveAssetStoreEvent> dispatch = assetStore.getEventBus().dispatchFor(RemoveAssetStoreEvent.class);
        if (dispatch.hasListener()) {
            dispatch.dispatch(new RemoveAssetStoreEvent(assetStore));
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public static int getTagIndex(@Nonnull String tag) {
        if (tag == null) {
            throw new IllegalArgumentException("tag can't be null!");
        }
        long stamp = TAG_LOCK.readLock();
        try {
            int n = TAG_MAP.getInt(tag);
            return n;
        }
        finally {
            TAG_LOCK.unlockRead(stamp);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public static int getOrCreateTagIndex(@Nonnull String tag) {
        if (tag == null) {
            throw new IllegalArgumentException("tag can't be null!");
        }
        long stamp = TAG_LOCK.writeLock();
        try {
            int n = TAG_MAP.computeIfAbsent(tag.intern(), k -> NEXT_TAG_INDEX.getAndIncrement());
            return n;
        }
        finally {
            TAG_LOCK.unlockWrite(stamp);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public static boolean registerClientTag(@Nonnull String tag) {
        if (tag == null) {
            throw new IllegalArgumentException("tag can't be null!");
        }
        long stamp = TAG_LOCK.writeLock();
        try {
            boolean bl = CLIENT_TAG_MAP.put(tag, TAG_MAP.computeIfAbsent(tag, k -> NEXT_TAG_INDEX.getAndIncrement())) == Integer.MIN_VALUE;
            return bl;
        }
        finally {
            TAG_LOCK.unlockWrite(stamp);
        }
    }

    @Nonnull
    public static Object2IntMap<String> getClientTags() {
        long stamp = TAG_LOCK.readLock();
        try {
            Object2IntOpenHashMap<String> object2IntOpenHashMap = new Object2IntOpenHashMap<String>(CLIENT_TAG_MAP);
            return object2IntOpenHashMap;
        }
        finally {
            TAG_LOCK.unlockRead(stamp);
        }
    }

    static {
        TAG_MAP.defaultReturnValue(Integer.MIN_VALUE);
        CLIENT_TAG_MAP.defaultReturnValue(Integer.MIN_VALUE);
    }
}

