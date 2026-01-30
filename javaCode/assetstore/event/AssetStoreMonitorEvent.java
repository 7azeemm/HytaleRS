/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.event;

import com.hypixel.hytale.assetstore.AssetStore;
import com.hypixel.hytale.assetstore.event.AssetMonitorEvent;
import java.nio.file.Path;
import java.util.List;
import javax.annotation.Nonnull;

public class AssetStoreMonitorEvent
extends AssetMonitorEvent<Void> {
    @Nonnull
    private final AssetStore<?, ?, ?> assetStore;

    public AssetStoreMonitorEvent(@Nonnull String assetPack, @Nonnull AssetStore<?, ?, ?> assetStore, @Nonnull List<Path> createdOrModified, @Nonnull List<Path> removed, @Nonnull List<Path> createdOrModifiedDirectories, @Nonnull List<Path> removedDirectories) {
        super(assetPack, createdOrModified, removed, createdOrModifiedDirectories, removedDirectories);
        this.assetStore = assetStore;
    }

    @Nonnull
    public AssetStore<?, ?, ?> getAssetStore() {
        return this.assetStore;
    }

    @Nonnull
    public String toString() {
        return "AssetMonitorEvent{assetStore=" + String.valueOf(this.assetStore) + "}";
    }
}

