/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.common;

import com.hypixel.hytale.protocol.Asset;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class PlayerCommonAssets {
    @Nonnull
    private final Map<String, String> assetMissing = new Object2ObjectOpenHashMap<String, String>();
    @Nonnull
    private final Map<String, String> assetSent;

    public PlayerCommonAssets(@Nonnull Asset[] requiredAssets) {
        for (Asset requiredAsset : requiredAssets) {
            this.assetMissing.put(requiredAsset.hash, requiredAsset.name);
        }
        this.assetSent = new Object2ObjectOpenHashMap<String, String>();
    }

    public void sent(@Nullable Asset[] hashes) {
        HashSet<String> set = new HashSet<String>();
        if (hashes != null) {
            for (Asset hash : hashes) {
                set.add(hash.hash);
            }
        }
        Iterator<String> iterator = this.assetMissing.keySet().iterator();
        while (iterator.hasNext()) {
            String hash = iterator.next();
            if (!set.contains(hash)) continue;
            iterator.remove();
            set.remove(hash);
        }
        if (!set.isEmpty()) {
            throw new RuntimeException("Still had hashes: " + String.valueOf(set));
        }
        this.assetSent.putAll(this.assetMissing);
        this.assetMissing.clear();
    }
}

