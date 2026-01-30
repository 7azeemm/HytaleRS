/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.common;

import com.hypixel.hytale.assetstore.AssetPack;
import com.hypixel.hytale.common.util.PatternUtil;
import com.hypixel.hytale.server.core.asset.common.CommonAsset;
import it.unimi.dsi.fastutil.booleans.BooleanObjectPair;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import it.unimi.dsi.fastutil.objects.ObjectArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class CommonAssetRegistry {
    private static final Map<String, List<PackAsset>> assetByNameMap = new ConcurrentHashMap<String, List<PackAsset>>();
    private static final Map<String, List<PackAsset>> assetByHashMap = new ConcurrentHashMap<String, List<PackAsset>>();
    private static final AtomicInteger duplicateAssetCount = new AtomicInteger();
    private static final Collection<List<PackAsset>> unmodifiableAssetByNameMapValues = Collections.unmodifiableCollection(assetByNameMap.values());

    public static int getDuplicateAssetCount() {
        return duplicateAssetCount.get();
    }

    @Nonnull
    public static Map<String, List<PackAsset>> getDuplicatedAssets() {
        Object2ObjectOpenHashMap<String, List<PackAsset>> duplicates = new Object2ObjectOpenHashMap<String, List<PackAsset>>();
        for (Map.Entry<String, List<PackAsset>> entry : assetByHashMap.entrySet()) {
            if (entry.getValue().size() <= 1) continue;
            duplicates.put(entry.getKey(), new ObjectArrayList((Collection)entry.getValue()));
        }
        return duplicates;
    }

    @Nonnull
    public static Collection<List<PackAsset>> getAllAssets() {
        return unmodifiableAssetByNameMapValues;
    }

    public static void clearAllAssets() {
        assetByNameMap.clear();
        assetByHashMap.clear();
    }

    @Nonnull
    public static AddCommonAssetResult addCommonAsset(String pack, @Nonnull CommonAsset asset) {
        AddCommonAssetResult result = new AddCommonAssetResult();
        result.newPackAsset = new PackAsset(pack, asset);
        List list = assetByNameMap.computeIfAbsent(asset.getName(), v -> new CopyOnWriteArrayList());
        boolean added = false;
        boolean addHash = true;
        for (int i = 0; i < list.size(); ++i) {
            PackAsset e = (PackAsset)list.get(i);
            if (!e.pack().equals(pack)) continue;
            result.previousNameAsset = e;
            if (i == list.size() - 1) {
                assetByHashMap.get(e.asset.getHash()).remove(e);
                assetByHashMap.compute(e.asset.getHash(), (k, v) -> v == null || v.isEmpty() ? null : v);
            } else {
                addHash = false;
            }
            list.set(i, result.newPackAsset);
            added = true;
            break;
        }
        if (!added) {
            if (!list.isEmpty()) {
                PackAsset e = (PackAsset)list.getLast();
                assetByHashMap.get(e.asset.getHash()).remove(e);
                assetByHashMap.compute(e.asset.getHash(), (k, v) -> v == null || v.isEmpty() ? null : v);
                result.previousNameAsset = e;
            }
            list.add(result.newPackAsset);
        }
        if (addHash) {
            List commonAssets = assetByHashMap.computeIfAbsent(asset.getHash(), k -> new CopyOnWriteArrayList());
            if (!commonAssets.isEmpty()) {
                result.previousHashAssets = (PackAsset[])commonAssets.toArray(PackAsset[]::new);
            }
            commonAssets.add(result.newPackAsset);
        }
        if (result.previousHashAssets != null || result.previousNameAsset != null) {
            result.duplicateAssetId = duplicateAssetCount.getAndIncrement();
        }
        result.activeAsset = (PackAsset)list.getLast();
        return result;
    }

    @Nullable
    public static BooleanObjectPair<PackAsset> removeCommonAssetByName(String pack, String name) {
        List<PackAsset> oldAssets = assetByNameMap.get(name = PatternUtil.replaceBackslashWithForwardSlash(name));
        if (oldAssets == null) {
            return null;
        }
        PackAsset previousCurrent = oldAssets.getLast();
        oldAssets.removeIf(v -> v.pack().equals(pack));
        assetByNameMap.compute(name, (k, v) -> v == null || v.isEmpty() ? null : v);
        if (oldAssets.isEmpty()) {
            CommonAssetRegistry.removeCommonAssetByHash0(previousCurrent);
            return BooleanObjectPair.of(false, previousCurrent);
        }
        PackAsset newCurrent = oldAssets.getLast();
        if (newCurrent.equals(previousCurrent)) {
            return null;
        }
        CommonAssetRegistry.removeCommonAssetByHash0(previousCurrent);
        assetByHashMap.computeIfAbsent(newCurrent.asset.getHash(), v -> new CopyOnWriteArrayList()).add(newCurrent);
        return BooleanObjectPair.of(true, newCurrent);
    }

    @Nonnull
    public static List<CommonAsset> getCommonAssetsStartingWith(String pack, String name) {
        ObjectArrayList<CommonAsset> oldAssets = new ObjectArrayList<CommonAsset>();
        for (List<PackAsset> assets : assetByNameMap.values()) {
            for (PackAsset asset : assets) {
                if (!asset.asset().getName().startsWith(name) || !asset.pack().equals(pack)) continue;
                oldAssets.add(asset.asset());
            }
        }
        return oldAssets;
    }

    public static boolean hasCommonAsset(String name) {
        return assetByNameMap.containsKey(name);
    }

    public static boolean hasCommonAsset(AssetPack pack, String name) {
        List<PackAsset> packAssets = assetByNameMap.get(name);
        if (packAssets != null) {
            for (PackAsset packAsset : packAssets) {
                if (!packAsset.pack.equals(pack.getName())) continue;
                return true;
            }
        }
        return false;
    }

    @Nullable
    public static CommonAsset getByName(String name) {
        List<PackAsset> asset = assetByNameMap.get(name = PatternUtil.replaceBackslashWithForwardSlash(name));
        return asset == null ? null : asset.getLast().asset();
    }

    @Nullable
    public static CommonAsset getByHash(@Nonnull String hash) {
        List<PackAsset> assets = assetByHashMap.get(hash.toLowerCase());
        return assets != null && !assets.isEmpty() ? assets.getFirst().asset() : null;
    }

    private static void removeCommonAssetByHash0(@Nonnull PackAsset oldAsset) {
        List<PackAsset> commonAssets = assetByHashMap.get(oldAsset.asset().getHash());
        if (commonAssets != null && commonAssets.remove(oldAsset) && commonAssets.isEmpty()) {
            assetByHashMap.compute(oldAsset.asset().getHash(), (key, assets) -> {
                if (assets == null || assets.isEmpty()) {
                    return null;
                }
                return assets;
            });
        }
    }

    public static class AddCommonAssetResult {
        private PackAsset newPackAsset;
        private PackAsset previousNameAsset;
        private PackAsset activeAsset;
        private PackAsset[] previousHashAssets;
        private int duplicateAssetId;

        public PackAsset getNewPackAsset() {
            return this.newPackAsset;
        }

        public PackAsset getPreviousNameAsset() {
            return this.previousNameAsset;
        }

        public PackAsset getActiveAsset() {
            return this.activeAsset;
        }

        public PackAsset[] getPreviousHashAssets() {
            return this.previousHashAssets;
        }

        public int getDuplicateAssetId() {
            return this.duplicateAssetId;
        }

        @Nonnull
        public String toString() {
            return "AddCommonAssetResult{previousNameAsset=" + String.valueOf(this.previousNameAsset) + ", previousHashAssets=" + Arrays.toString(this.previousHashAssets) + ", duplicateAssetId=" + this.duplicateAssetId + "}";
        }
    }

    public record PackAsset(String pack, CommonAsset asset) {
        @Override
        public boolean equals(@Nullable Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || this.getClass() != o.getClass()) {
                return false;
            }
            PackAsset packAsset = (PackAsset)o;
            if (!this.pack.equals(packAsset.pack)) {
                return false;
            }
            return this.asset.equals(packAsset.asset);
        }

        @Override
        @Nonnull
        public String toString() {
            return "PackAsset{pack='" + this.pack + "', asset=" + String.valueOf(this.asset) + "}";
        }
    }
}

