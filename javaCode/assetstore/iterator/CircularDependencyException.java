/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.iterator;

import com.hypixel.hytale.assetstore.AssetRegistry;
import com.hypixel.hytale.assetstore.AssetStore;
import com.hypixel.hytale.assetstore.JsonAsset;
import com.hypixel.hytale.assetstore.iterator.AssetStoreIterator;
import java.util.Collection;
import javax.annotation.Nonnull;

public class CircularDependencyException
extends RuntimeException {
    public CircularDependencyException(@Nonnull Collection<AssetStore<?, ?, ?>> values, @Nonnull AssetStoreIterator iterator) {
        super(CircularDependencyException.makeMessage(values, iterator));
    }

    @Nonnull
    protected static String makeMessage(@Nonnull Collection<AssetStore<?, ?, ?>> values, @Nonnull AssetStoreIterator iterator) {
        StringBuilder sb = new StringBuilder("Failed to process any stores there must be a circular dependency! " + String.valueOf(values) + ", " + iterator.size() + "\nWaiting for Asset Stores:\n");
        for (AssetStore<?, ?, ?> store : values) {
            if (!iterator.isWaitingForDependencies(store)) continue;
            sb.append(store.getAssetClass()).append("\n");
            for (Class<JsonAsset<?>> aClass : store.getLoadsAfter()) {
                AssetStore otherStore = AssetRegistry.getAssetStore(aClass);
                if (otherStore == null) {
                    throw new IllegalArgumentException("Unable to find asset store: " + String.valueOf(aClass));
                }
                if (!iterator.isWaitingForDependencies(otherStore)) continue;
                sb.append("\t- ").append(otherStore.getAssetClass()).append("\n");
            }
        }
        return sb.toString();
    }
}

