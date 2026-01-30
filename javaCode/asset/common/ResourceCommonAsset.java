/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.common;

import com.hypixel.hytale.server.core.asset.common.CommonAsset;
import com.hypixel.hytale.sneakythrow.SneakyThrow;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.CompletableFuture;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class ResourceCommonAsset
extends CommonAsset {
    private final Class<?> clazz;
    private final String path;

    public ResourceCommonAsset(Class<?> clazz, String path, @Nonnull String name, byte[] bytes) {
        super(name, bytes);
        this.clazz = clazz;
        this.path = path;
    }

    public ResourceCommonAsset(Class<?> clazz, String path, @Nonnull String name, @Nonnull String hash, byte[] bytes) {
        super(name, hash, bytes);
        this.clazz = clazz;
        this.path = path;
    }

    public String getPath() {
        return this.path;
    }

    @Override
    @Nonnull
    public CompletableFuture<byte[]> getBlob0() {
        CompletableFuture<byte[]> completableFuture;
        block8: {
            InputStream stream = this.clazz.getResourceAsStream(this.path);
            try {
                completableFuture = CompletableFuture.completedFuture(stream.readAllBytes());
                if (stream == null) break block8;
            }
            catch (Throwable throwable) {
                try {
                    if (stream != null) {
                        try {
                            stream.close();
                        }
                        catch (Throwable throwable2) {
                            throwable.addSuppressed(throwable2);
                        }
                    }
                    throw throwable;
                }
                catch (IOException e) {
                    return CompletableFuture.failedFuture(e);
                }
            }
            stream.close();
        }
        return completableFuture;
    }

    @Override
    @Nonnull
    public String toString() {
        return "ResourceCommonAsset{" + super.toString() + "}";
    }

    /*
     * Enabled aggressive block sorting
     * Enabled unnecessary exception pruning
     * Enabled aggressive exception aggregation
     */
    @Nullable
    public static ResourceCommonAsset of(@Nonnull Class<?> clazz, @Nonnull String path, @Nonnull String name) {
        try (InputStream stream = clazz.getResourceAsStream(path);){
            if (stream == null) {
                ResourceCommonAsset resourceCommonAsset2 = null;
                return resourceCommonAsset2;
            }
            byte[] bytes = stream.readAllBytes();
            ResourceCommonAsset resourceCommonAsset = new ResourceCommonAsset(clazz, path, name, bytes);
            return resourceCommonAsset;
        }
        catch (IOException e) {
            throw SneakyThrow.sneakyThrow(e);
        }
    }
}

