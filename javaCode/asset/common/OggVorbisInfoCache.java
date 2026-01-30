/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.common;

import com.hypixel.hytale.common.util.CompletableFutureUtil;
import com.hypixel.hytale.logger.HytaleLogger;
import com.hypixel.hytale.server.core.asset.common.CommonAsset;
import com.hypixel.hytale.server.core.asset.common.CommonAssetRegistry;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class OggVorbisInfoCache {
    public static final HytaleLogger LOGGER = HytaleLogger.forEnclosingClass();
    private static final Map<String, OggVorbisInfo> vorbisFiles = new ConcurrentHashMap<String, OggVorbisInfo>();

    @Nonnull
    public static CompletableFuture<OggVorbisInfo> get(String name) {
        OggVorbisInfo info = vorbisFiles.get(name);
        if (info != null) {
            return CompletableFuture.completedFuture(info);
        }
        CommonAsset asset = CommonAssetRegistry.getByName(name);
        if (asset == null) {
            return CompletableFuture.completedFuture(null);
        }
        return OggVorbisInfoCache.get0(asset);
    }

    @Nonnull
    public static CompletableFuture<OggVorbisInfo> get(@Nonnull CommonAsset asset) {
        OggVorbisInfo info = vorbisFiles.get(asset.getName());
        if (info != null) {
            return CompletableFuture.completedFuture(info);
        }
        return OggVorbisInfoCache.get0(asset);
    }

    @Nullable
    public static OggVorbisInfo getNow(String name) {
        OggVorbisInfo info = vorbisFiles.get(name);
        if (info != null) {
            return info;
        }
        CommonAsset asset = CommonAssetRegistry.getByName(name);
        if (asset == null) {
            return null;
        }
        return OggVorbisInfoCache.get0(asset).join();
    }

    public static OggVorbisInfo getNow(@Nonnull CommonAsset asset) {
        OggVorbisInfo info = vorbisFiles.get(asset.getName());
        if (info != null) {
            return info;
        }
        return OggVorbisInfoCache.get0(asset).join();
    }

    @Nonnull
    private static CompletableFuture<OggVorbisInfo> get0(@Nonnull CommonAsset asset) {
        String name = asset.getName();
        return CompletableFutureUtil._catch(asset.getBlob().thenApply(bytes -> {
            ByteBuf b = Unpooled.wrappedBuffer(bytes);
            try {
                int len = b.readableBytes();
                int id = -1;
                int end = len - 7;
                for (int i = 0; i <= end && (i = b.indexOf(i, len - 7, (byte)1)) != -1; ++i) {
                    if (b.getByte(i + 1) != 118 || b.getByte(i + 2) != 111 || b.getByte(i + 3) != 114 || b.getByte(i + 4) != 98 || b.getByte(i + 5) != 105 || b.getByte(i + 6) != 115) continue;
                    id = i;
                    break;
                }
                if (id < 0 || id + 16 > len) {
                    throw new IllegalArgumentException("Vorbis id header not found");
                }
                short channels = b.getUnsignedByte(id + 11);
                int sampleRate = b.getIntLE(id + 12);
                double duration = -1.0;
                if (sampleRate > 0) {
                    for (int i = Math.max(0, len - 14); i >= 0 && (i = b.indexOf(i, 0, (byte)79)) != -1; --i) {
                        short headerType;
                        if (b.getByte(i + 1) != 103 || b.getByte(i + 2) != 103 || b.getByte(i + 3) != 83 || ((headerType = b.getUnsignedByte(i + 5)) & 4) == 0) continue;
                        long granule = b.getLongLE(i + 6);
                        if (granule < 0L) break;
                        duration = (double)granule / (double)sampleRate;
                        break;
                    }
                }
                OggVorbisInfo info = new OggVorbisInfo(channels, sampleRate, duration);
                vorbisFiles.put(name, info);
                OggVorbisInfo oggVorbisInfo = info;
                return oggVorbisInfo;
            }
            finally {
                b.release();
            }
        }));
    }

    public static void invalidate(String name) {
        vorbisFiles.remove(name);
    }

    public static class OggVorbisInfo {
        public final int channels;
        public final int sampleRate;
        public final double duration;

        OggVorbisInfo(int channels, int sampleRate, double duration) {
            this.channels = channels;
            this.sampleRate = sampleRate;
            this.duration = duration;
        }

        @Nonnull
        public String toString() {
            return "OggVorbisInfo{channels=" + this.channels + ", sampleRate=" + this.sampleRate + ", duration=" + this.duration + "}";
        }
    }
}

