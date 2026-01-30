/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.common;

import com.hypixel.hytale.codec.Codec;
import com.hypixel.hytale.codec.ExtraInfo;
import com.hypixel.hytale.codec.KeyedCodec;
import com.hypixel.hytale.codec.builder.BuilderCodec;
import com.hypixel.hytale.codec.util.RawJsonReader;
import com.hypixel.hytale.common.util.CompletableFutureUtil;
import com.hypixel.hytale.logger.HytaleLogger;
import com.hypixel.hytale.server.core.asset.common.CommonAsset;
import com.hypixel.hytale.server.core.asset.common.CommonAssetRegistry;
import com.hypixel.hytale.sneakythrow.SneakyThrow;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BlockyAnimationCache {
    public static final HytaleLogger LOGGER = HytaleLogger.forEnclosingClass();
    private static final Map<String, BlockyAnimation> animations = new ConcurrentHashMap<String, BlockyAnimation>();

    @Nonnull
    public static CompletableFuture<BlockyAnimation> get(String name) {
        BlockyAnimation animationData = animations.get(name);
        if (animationData != null) {
            return CompletableFuture.completedFuture(animationData);
        }
        CommonAsset asset = CommonAssetRegistry.getByName(name);
        if (asset == null) {
            return CompletableFuture.completedFuture(null);
        }
        return BlockyAnimationCache.get0(asset);
    }

    @Nonnull
    public static CompletableFuture<BlockyAnimation> get(@Nonnull CommonAsset asset) {
        BlockyAnimation animationData = animations.get(asset.getName());
        if (animationData != null) {
            return CompletableFuture.completedFuture(animationData);
        }
        return BlockyAnimationCache.get0(asset);
    }

    @Nullable
    public static BlockyAnimation getNow(String name) {
        BlockyAnimation animationData = animations.get(name);
        if (animationData != null) {
            return animationData;
        }
        CommonAsset asset = CommonAssetRegistry.getByName(name);
        if (asset == null) {
            return null;
        }
        return BlockyAnimationCache.get0(asset).join();
    }

    public static BlockyAnimation getNow(@Nonnull CommonAsset asset) {
        BlockyAnimation animationData = animations.get(asset.getName());
        if (animationData != null) {
            return animationData;
        }
        return BlockyAnimationCache.get0(asset).join();
    }

    @Nonnull
    private static CompletableFuture<BlockyAnimation> get0(@Nonnull CommonAsset asset) {
        String name = asset.getName();
        return CompletableFutureUtil._catch(asset.getBlob().thenApply(bytes -> {
            String str = new String((byte[])bytes, StandardCharsets.UTF_8);
            RawJsonReader reader = RawJsonReader.fromJsonString(str);
            try {
                ExtraInfo extraInfo = ExtraInfo.THREAD_LOCAL.get();
                BlockyAnimation newAnimationData = BlockyAnimation.CODEC.decodeJson(reader, extraInfo);
                extraInfo.getValidationResults().logOrThrowValidatorExceptions(LOGGER);
                animations.put(name, newAnimationData);
                return newAnimationData;
            }
            catch (IOException e) {
                throw SneakyThrow.sneakyThrow(e);
            }
        }));
    }

    public static void invalidate(String name) {
        animations.remove(name);
    }

    public static class BlockyAnimation {
        public static final BuilderCodec<BlockyAnimation> CODEC = ((BuilderCodec.Builder)BuilderCodec.builder(BlockyAnimation.class, BlockyAnimation::new).addField(new KeyedCodec<Integer>("duration", Codec.INTEGER, true, true), (blockyAnimation, i) -> {
            blockyAnimation.duration = i;
        }, blockyAnimation -> blockyAnimation.duration)).build();
        public static final double FRAMES_PER_SECOND = 60.0;
        private int duration;

        public int getDurationFrames() {
            return this.duration;
        }

        public double getDurationMillis() {
            return (double)this.duration * 1000.0 / 60.0;
        }

        public double getDurationSeconds() {
            return (double)this.duration / 60.0;
        }

        @Nonnull
        public String toString() {
            return "BlockyAnimation{duration=" + this.duration + "}";
        }
    }
}

