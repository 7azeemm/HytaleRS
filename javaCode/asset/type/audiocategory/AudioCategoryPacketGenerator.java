/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.type.audiocategory;

import com.hypixel.hytale.assetstore.map.IndexedLookupTableAssetMap;
import com.hypixel.hytale.protocol.Packet;
import com.hypixel.hytale.protocol.UpdateType;
import com.hypixel.hytale.protocol.packets.assets.UpdateAudioCategories;
import com.hypixel.hytale.server.core.asset.packet.SimpleAssetPacketGenerator;
import com.hypixel.hytale.server.core.asset.type.audiocategory.config.AudioCategory;
import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

public class AudioCategoryPacketGenerator
extends SimpleAssetPacketGenerator<String, AudioCategory, IndexedLookupTableAssetMap<String, AudioCategory>> {
    @Override
    @Nonnull
    public Packet generateInitPacket(@Nonnull IndexedLookupTableAssetMap<String, AudioCategory> assetMap, @Nonnull Map<String, AudioCategory> assets) {
        UpdateAudioCategories packet = new UpdateAudioCategories();
        packet.type = UpdateType.Init;
        packet.categories = new Int2ObjectOpenHashMap<com.hypixel.hytale.protocol.AudioCategory>(assets.size());
        for (Map.Entry<String, AudioCategory> entry : assets.entrySet()) {
            String key = entry.getKey();
            int index = assetMap.getIndex(key);
            if (index == Integer.MIN_VALUE) {
                throw new IllegalArgumentException("Unknown key! " + key);
            }
            packet.categories.put(index, entry.getValue().toPacket());
        }
        packet.maxId = assetMap.getNextIndex();
        return packet;
    }

    @Override
    @Nonnull
    public Packet generateUpdatePacket(@Nonnull IndexedLookupTableAssetMap<String, AudioCategory> assetMap, @Nonnull Map<String, AudioCategory> loadedAssets) {
        UpdateAudioCategories packet = new UpdateAudioCategories();
        packet.type = UpdateType.AddOrUpdate;
        packet.categories = new Int2ObjectOpenHashMap<com.hypixel.hytale.protocol.AudioCategory>(loadedAssets.size());
        for (Map.Entry<String, AudioCategory> entry : loadedAssets.entrySet()) {
            String key = entry.getKey();
            int index = assetMap.getIndex(key);
            if (index == Integer.MIN_VALUE) {
                throw new IllegalArgumentException("Unknown key! " + key);
            }
            packet.categories.put(index, entry.getValue().toPacket());
        }
        packet.maxId = assetMap.getNextIndex();
        return packet;
    }

    @Override
    @Nonnull
    public Packet generateRemovePacket(@Nonnull IndexedLookupTableAssetMap<String, AudioCategory> assetMap, @Nonnull Set<String> removed) {
        UpdateAudioCategories packet = new UpdateAudioCategories();
        packet.type = UpdateType.Remove;
        packet.categories = new Int2ObjectOpenHashMap<com.hypixel.hytale.protocol.AudioCategory>(removed.size());
        for (String key : removed) {
            int index = assetMap.getIndex(key);
            if (index == Integer.MIN_VALUE) {
                throw new IllegalArgumentException("Unknown key! " + key);
            }
            packet.categories.put(index, null);
        }
        packet.maxId = assetMap.getNextIndex();
        return packet;
    }
}

