/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.type.blockset.config;

import com.hypixel.hytale.assetstore.AssetExtraInfo;
import com.hypixel.hytale.assetstore.AssetKeyValidator;
import com.hypixel.hytale.assetstore.AssetRegistry;
import com.hypixel.hytale.assetstore.AssetStore;
import com.hypixel.hytale.assetstore.codec.AssetBuilderCodec;
import com.hypixel.hytale.assetstore.map.IndexedLookupTableAssetMap;
import com.hypixel.hytale.assetstore.map.JsonAssetWithMap;
import com.hypixel.hytale.codec.Codec;
import com.hypixel.hytale.codec.KeyedCodec;
import com.hypixel.hytale.codec.codecs.array.ArrayCodec;
import com.hypixel.hytale.codec.schema.metadata.ui.UIEditorSectionStart;
import com.hypixel.hytale.codec.validation.ValidatorCache;
import com.hypixel.hytale.server.core.io.NetworkSerializable;
import com.hypixel.hytale.server.core.modules.blockset.BlockSetModule;
import it.unimi.dsi.fastutil.ints.IntSet;
import java.util.Arrays;
import javax.annotation.Nonnull;

@Deprecated(forRemoval=true)
public class BlockSet
implements JsonAssetWithMap<String, IndexedLookupTableAssetMap<String, BlockSet>>,
NetworkSerializable<com.hypixel.hytale.protocol.BlockSet> {
    public static final AssetBuilderCodec<String, BlockSet> CODEC = ((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)AssetBuilderCodec.builder(BlockSet.class, BlockSet::new, Codec.STRING, (t, k) -> {
        t.id = k;
    }, t -> t.id, (asset, data) -> {
        asset.data = data;
    }, asset -> asset.data).append(new KeyedCodec<String>("Parent", Codec.STRING), (blockSet, b) -> {
        blockSet.parent = b;
    }, blockSet -> blockSet.parent).metadata(new UIEditorSectionStart("General")).add()).addField(new KeyedCodec<Boolean>("IncludeAll", Codec.BOOLEAN), (blockSet, b) -> {
        blockSet.includeAll = b;
    }, blockSet -> blockSet.includeAll)).addField(new KeyedCodec<T[]>("IncludeBlockTypes", Codec.STRING_ARRAY), (blockSet, strings) -> {
        blockSet.includeBlockTypes = strings;
    }, blockSet -> blockSet.includeBlockTypes)).addField(new KeyedCodec<T[]>("ExcludeBlockTypes", Codec.STRING_ARRAY), (blockSet, strings) -> {
        blockSet.excludeBlockTypes = strings;
    }, blockSet -> blockSet.excludeBlockTypes)).addField(new KeyedCodec<T[]>("IncludeBlockGroups", Codec.STRING_ARRAY), (blockSet, strings) -> {
        blockSet.includeBlockGroups = strings;
    }, blockSet -> blockSet.includeBlockGroups)).addField(new KeyedCodec<T[]>("ExcludeBlockGroups", Codec.STRING_ARRAY), (blockSet, strings) -> {
        blockSet.excludeBlockGroups = strings;
    }, blockSet -> blockSet.excludeBlockGroups)).addField(new KeyedCodec<T[]>("IncludeHitboxTypes", Codec.STRING_ARRAY), (blockSet, strings) -> {
        blockSet.includeHitboxTypes = strings;
    }, blockSet -> blockSet.includeHitboxTypes)).addField(new KeyedCodec<T[]>("ExcludeHitboxTypes", Codec.STRING_ARRAY), (blockSet, strings) -> {
        blockSet.excludeHitboxTypes = strings;
    }, blockSet -> blockSet.excludeHitboxTypes)).addField(new KeyedCodec<T[]>("IncludeCategories", new ArrayCodec<T[]>(Codec.STRING_ARRAY, x$0 -> new String[x$0][])), (blockSet, strings) -> {
        blockSet.includeCategories = strings;
    }, blockSet -> blockSet.includeCategories)).addField(new KeyedCodec<T[]>("ExcludeCategories", new ArrayCodec<T[]>(Codec.STRING_ARRAY, x$0 -> new String[x$0][])), (blockSet, strings) -> {
        blockSet.excludeCategories = strings;
    }, blockSet -> blockSet.excludeCategories)).build();
    public static final ValidatorCache<String> VALIDATOR_CACHE = new ValidatorCache(new AssetKeyValidator(BlockSet::getAssetStore));
    private static AssetStore<String, BlockSet, IndexedLookupTableAssetMap<String, BlockSet>> ASSET_STORE;
    protected AssetExtraInfo.Data data;
    protected String id;
    protected String parent;
    protected boolean includeAll;
    protected String[] includeBlockTypes;
    protected String[] excludeBlockTypes;
    protected String[] includeBlockGroups;
    protected String[] excludeBlockGroups;
    protected String[] includeHitboxTypes;
    protected String[] excludeHitboxTypes;
    protected String[][] includeCategories;
    protected String[][] excludeCategories;

    public static AssetStore<String, BlockSet, IndexedLookupTableAssetMap<String, BlockSet>> getAssetStore() {
        if (ASSET_STORE == null) {
            ASSET_STORE = AssetRegistry.getAssetStore(BlockSet.class);
        }
        return ASSET_STORE;
    }

    public static IndexedLookupTableAssetMap<String, BlockSet> getAssetMap() {
        return BlockSet.getAssetStore().getAssetMap();
    }

    public BlockSet(String id) {
        this.id = id;
    }

    public BlockSet(String id, String parent, boolean includeAll, String[] includeBlockTypes, String[] excludeBlockTypes, String[] includeBlockGroups, String[] excludeBlockGroups, String[] includeHitboxTypes, String[] excludeHitboxTypes, String[][] includeCategories, String[][] excludeCategories) {
        this.id = id;
        this.parent = parent;
        this.includeAll = includeAll;
        this.includeBlockTypes = includeBlockTypes;
        this.excludeBlockTypes = excludeBlockTypes;
        this.includeBlockGroups = includeBlockGroups;
        this.excludeBlockGroups = excludeBlockGroups;
        this.includeHitboxTypes = includeHitboxTypes;
        this.excludeHitboxTypes = excludeHitboxTypes;
        this.includeCategories = includeCategories;
        this.excludeCategories = excludeCategories;
    }

    protected BlockSet() {
    }

    @Override
    public String getId() {
        return this.id;
    }

    public String getParent() {
        return this.parent;
    }

    public boolean isIncludeAll() {
        return this.includeAll;
    }

    public String[] getIncludeBlockTypes() {
        return this.includeBlockTypes;
    }

    public String[] getExcludeBlockTypes() {
        return this.excludeBlockTypes;
    }

    public String[] getIncludeBlockGroups() {
        return this.includeBlockGroups;
    }

    public String[] getExcludeBlockGroups() {
        return this.excludeBlockGroups;
    }

    public String[] getIncludeHitboxTypes() {
        return this.includeHitboxTypes;
    }

    public String[] getExcludeHitboxTypes() {
        return this.excludeHitboxTypes;
    }

    public String[][] getIncludeCategories() {
        return this.includeCategories;
    }

    public String[][] getExcludeCategories() {
        return this.excludeCategories;
    }

    @Nonnull
    public String toString() {
        return "BlockSet{name='" + this.id + "', parent='" + this.parent + "', includeAll=" + this.includeAll + ", includeBlockTypes=" + Arrays.toString(this.includeBlockTypes) + ", excludeBlockTypes=" + Arrays.toString(this.excludeBlockTypes) + ", includeBlockGroups=" + Arrays.toString(this.includeBlockGroups) + ", excludeBlockGroups=" + Arrays.toString(this.excludeBlockGroups) + ", includeHitboxTypes=" + Arrays.toString(this.includeHitboxTypes) + ", excludeHitboxTypes=" + Arrays.toString(this.excludeHitboxTypes) + ", includeCategories=" + Arrays.deepToString((Object[])this.includeCategories) + ", excludeCategories=" + Arrays.deepToString((Object[])this.excludeCategories) + "}";
    }

    @Override
    @Nonnull
    public com.hypixel.hytale.protocol.BlockSet toPacket() {
        com.hypixel.hytale.protocol.BlockSet packet = new com.hypixel.hytale.protocol.BlockSet();
        int index = BlockSet.getAssetMap().getIndex(this.id);
        IntSet allBlocks = (IntSet)BlockSetModule.getInstance().getBlockSets().get(index);
        packet.name = this.id;
        packet.blocks = allBlocks.toIntArray();
        return packet;
    }
}

