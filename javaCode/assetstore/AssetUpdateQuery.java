/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore;

import com.hypixel.hytale.assetstore.AssetStore;
import javax.annotation.Nonnull;

public class AssetUpdateQuery {
    public static final AssetUpdateQuery DEFAULT = new AssetUpdateQuery(RebuildCache.DEFAULT);
    public static final AssetUpdateQuery DEFAULT_NO_REBUILD = new AssetUpdateQuery(RebuildCache.NO_REBUILD);
    private final boolean disableAssetCompare;
    private final RebuildCache rebuildCache;

    public AssetUpdateQuery(boolean disableAssetCompare, RebuildCache rebuildCache) {
        this.disableAssetCompare = disableAssetCompare;
        this.rebuildCache = rebuildCache;
    }

    public AssetUpdateQuery(RebuildCache rebuildCache) {
        this(AssetStore.DISABLE_ASSET_COMPARE, rebuildCache);
    }

    public boolean isDisableAssetCompare() {
        return this.disableAssetCompare;
    }

    @Nonnull
    public RebuildCache getRebuildCache() {
        return this.rebuildCache;
    }

    @Nonnull
    public String toString() {
        return "AssetUpdateQuery{rebuildCache=" + String.valueOf(this.rebuildCache) + "}";
    }

    public static class RebuildCache {
        public static final RebuildCache DEFAULT = new RebuildCache(true, true, true, true, true, true);
        public static final RebuildCache NO_REBUILD = new RebuildCache(false, false, false, false, false, false);
        private final boolean blockTextures;
        private final boolean models;
        private final boolean modelTextures;
        private final boolean mapGeometry;
        private final boolean itemIcons;
        private final boolean commonAssetsRebuild;

        public RebuildCache(boolean blockTextures, boolean models, boolean modelTextures, boolean mapGeometry, boolean itemIcons, boolean commonAssetsRebuild) {
            this.blockTextures = blockTextures;
            this.models = models;
            this.modelTextures = modelTextures;
            this.mapGeometry = mapGeometry;
            this.itemIcons = itemIcons;
            this.commonAssetsRebuild = commonAssetsRebuild;
        }

        public boolean isBlockTextures() {
            return this.blockTextures;
        }

        public boolean isModels() {
            return this.models;
        }

        public boolean isModelTextures() {
            return this.modelTextures;
        }

        public boolean isMapGeometry() {
            return this.mapGeometry;
        }

        public boolean isItemIcons() {
            return this.itemIcons;
        }

        public boolean isCommonAssetsRebuild() {
            return this.commonAssetsRebuild;
        }

        @Nonnull
        public RebuildCacheBuilder toBuilder() {
            return new RebuildCacheBuilder(this.blockTextures, this.models, this.modelTextures, this.mapGeometry, this.itemIcons, this.commonAssetsRebuild);
        }

        @Nonnull
        public static RebuildCacheBuilder builder() {
            return new RebuildCacheBuilder();
        }

        @Nonnull
        public String toString() {
            return "RebuildCache{blockTextures=" + this.blockTextures + ", models=" + this.models + ", modelTextures=" + this.modelTextures + ", mapGeometry=" + this.mapGeometry + ", icons=" + this.itemIcons + ", commonAssetsRebuild=" + this.commonAssetsRebuild + "}";
        }
    }

    public static class RebuildCacheBuilder {
        private boolean blockTextures;
        private boolean models;
        private boolean modelTextures;
        private boolean mapGeometry;
        private boolean itemIcons;
        private boolean commonAssetsRebuild;

        RebuildCacheBuilder() {
        }

        RebuildCacheBuilder(boolean blockTextures, boolean models, boolean modelTextures, boolean mapGeometry, boolean itemIcons, boolean commonAssetsRebuild) {
            this.blockTextures = blockTextures;
            this.models = models;
            this.modelTextures = modelTextures;
            this.mapGeometry = mapGeometry;
            this.itemIcons = itemIcons;
            this.commonAssetsRebuild = commonAssetsRebuild;
        }

        public void setBlockTextures(boolean blockTextures) {
            this.blockTextures = blockTextures;
        }

        public void setModels(boolean models) {
            this.models = models;
        }

        public void setModelTextures(boolean modelTextures) {
            this.modelTextures = modelTextures;
        }

        public void setMapGeometry(boolean mapGeometry) {
            this.mapGeometry = mapGeometry;
        }

        public void setItemIcons(boolean itemIcons) {
            this.itemIcons = itemIcons;
        }

        public void setCommonAssetsRebuild(boolean commonAssetsRebuild) {
            this.commonAssetsRebuild = commonAssetsRebuild;
        }

        @Nonnull
        public RebuildCache build() {
            return new RebuildCache(this.blockTextures, this.models, this.modelTextures, this.mapGeometry, this.itemIcons, this.commonAssetsRebuild);
        }

        @Nonnull
        public String toString() {
            return "RebuildCache{blockTextures=" + this.blockTextures + ", models=" + this.models + ", modelTextures=" + this.modelTextures + ", mapGeometry=" + this.mapGeometry + ", icons=" + this.itemIcons + ", commonAssetsRebuild=" + this.commonAssetsRebuild + "}";
        }
    }
}

