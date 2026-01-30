/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.iterator;

import com.hypixel.hytale.assetstore.AssetRegistry;
import com.hypixel.hytale.assetstore.AssetStore;
import com.hypixel.hytale.assetstore.JsonAsset;
import java.io.Closeable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class AssetStoreIterator
implements Iterator<AssetStore<?, ?, ?>>,
Closeable {
    @Nonnull
    private final List<AssetStore<?, ?, ?>> list;

    public AssetStoreIterator(@Nonnull Collection<AssetStore<?, ?, ?>> values) {
        this.list = new ArrayList(values);
    }

    @Override
    public boolean hasNext() {
        return !this.list.isEmpty();
    }

    @Override
    @Nullable
    public AssetStore<?, ?, ?> next() {
        Iterator<AssetStore<?, ?, ?>> iterator = this.list.iterator();
        while (iterator.hasNext()) {
            AssetStore<?, ?, ?> assetStore = iterator.next();
            if (this.isWaitingForDependencies(assetStore)) continue;
            iterator.remove();
            return assetStore;
        }
        return null;
    }

    public int size() {
        return this.list.size();
    }

    public boolean isWaitingForDependencies(@Nonnull AssetStore<?, ?, ?> assetStore) {
        for (Class<JsonAsset<?>> aClass : assetStore.getLoadsAfter()) {
            AssetStore otherStore = AssetRegistry.getAssetStore(aClass);
            if (otherStore == null) {
                throw new IllegalArgumentException("Unable to find asset store: " + String.valueOf(aClass));
            }
            if (!this.list.contains(otherStore)) continue;
            return true;
        }
        return false;
    }

    public boolean isBeingWaitedFor(@Nonnull AssetStore<?, ?, ?> assetStore) {
        Class<?> assetClass = assetStore.getAssetClass();
        for (AssetStore<?, ?, ?> store : this.list) {
            if (!store.getLoadsAfter().contains(assetClass)) continue;
            return true;
        }
        return false;
    }

    @Override
    public void close() {
    }
}

