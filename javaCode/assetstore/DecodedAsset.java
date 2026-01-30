/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore;

import com.hypixel.hytale.assetstore.AssetHolder;
import com.hypixel.hytale.assetstore.JsonAsset;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DecodedAsset<K, T extends JsonAsset<K>>
implements AssetHolder<K> {
    private final K key;
    private final T asset;

    public DecodedAsset(K key, T asset) {
        this.key = key;
        this.asset = asset;
    }

    public K getKey() {
        return this.key;
    }

    public T getAsset() {
        return this.asset;
    }

    public boolean equals(@Nullable Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || this.getClass() != o.getClass()) {
            return false;
        }
        DecodedAsset that = (DecodedAsset)o;
        if (this.key != null ? !this.key.equals(that.key) : that.key != null) {
            return false;
        }
        return this.asset != null ? this.asset.equals(that.asset) : that.asset == null;
    }

    public int hashCode() {
        int result = this.key != null ? this.key.hashCode() : 0;
        result = 31 * result + (this.asset != null ? this.asset.hashCode() : 0);
        return result;
    }

    @Nonnull
    public String toString() {
        return "DecodedAsset{key=" + String.valueOf(this.key) + ", asset=" + String.valueOf(this.asset) + "}";
    }
}

