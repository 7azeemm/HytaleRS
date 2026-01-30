/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.common;

import com.hypixel.hytale.common.util.PatternUtil;
import com.hypixel.hytale.protocol.Asset;
import com.hypixel.hytale.server.core.io.NetworkSerializable;
import com.hypixel.hytale.server.core.util.HashUtil;
import java.lang.ref.SoftReference;
import java.lang.ref.WeakReference;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public abstract class CommonAsset
implements NetworkSerializable<Asset> {
    public static final int HASH_LENGTH = 64;
    public static final Pattern HASH_PATTERN = Pattern.compile("^[A-Fa-f0-9]{64}$");
    @Nonnull
    private final String name;
    @Nonnull
    private final String hash;
    protected transient WeakReference<CompletableFuture<byte[]>> blob;
    protected transient SoftReference<Asset> cachedPacket;

    public CommonAsset(@Nonnull String name, @Nullable byte[] bytes) {
        this.name = PatternUtil.replaceBackslashWithForwardSlash(name);
        this.hash = CommonAsset.hash(bytes);
        this.blob = new WeakReference<CompletableFuture<byte[]>>(bytes != null ? CompletableFuture.completedFuture(bytes) : null);
    }

    public CommonAsset(@Nonnull String name, @Nonnull String hash, @Nullable byte[] bytes) {
        this.name = PatternUtil.replaceBackslashWithForwardSlash(name);
        this.hash = hash.toLowerCase();
        this.blob = new WeakReference<CompletableFuture<byte[]>>(bytes != null ? CompletableFuture.completedFuture(bytes) : null);
    }

    @Nonnull
    public String getName() {
        return this.name;
    }

    @Nonnull
    public String getHash() {
        return this.hash;
    }

    public CompletableFuture<byte[]> getBlob() {
        CompletableFuture<byte[]> future = (CompletableFuture<byte[]>)this.blob.get();
        if (future == null) {
            future = this.getBlob0();
            this.blob = new WeakReference<CompletableFuture<byte[]>>(future);
        }
        return future;
    }

    protected abstract CompletableFuture<byte[]> getBlob0();

    @Override
    @Nonnull
    public Asset toPacket() {
        Asset cached;
        Asset asset = cached = this.cachedPacket == null ? null : this.cachedPacket.get();
        if (cached != null) {
            return cached;
        }
        Asset packet = new Asset(this.hash, this.name);
        this.cachedPacket = new SoftReference<Asset>(packet);
        return packet;
    }

    public boolean equals(@Nullable Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || this.getClass() != o.getClass()) {
            return false;
        }
        CommonAsset asset = (CommonAsset)o;
        if (!this.name.equals(asset.name)) {
            return false;
        }
        return this.hash.equals(asset.hash);
    }

    public int hashCode() {
        int result = this.name.hashCode();
        result = 31 * result + this.hash.hashCode();
        return result;
    }

    @Nonnull
    public String toString() {
        return "CommonAsset{name='" + this.name + "', hash='" + this.hash + "'}";
    }

    @Nonnull
    public static String hash(byte[] bytes) {
        return HashUtil.sha256(bytes);
    }
}

