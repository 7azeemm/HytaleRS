/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.type.blockhitbox;

import com.hypixel.hytale.assetstore.map.IndexedLookupTableAssetMap;
import com.hypixel.hytale.protocol.Hitbox;
import com.hypixel.hytale.protocol.Packet;
import com.hypixel.hytale.protocol.UpdateType;
import com.hypixel.hytale.protocol.packets.assets.UpdateBlockHitboxes;
import com.hypixel.hytale.server.core.asset.packet.SimpleAssetPacketGenerator;
import com.hypixel.hytale.server.core.asset.type.blockhitbox.BlockBoundingBoxes;
import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

public class BlockBoundingBoxesPacketGenerator
extends SimpleAssetPacketGenerator<String, BlockBoundingBoxes, IndexedLookupTableAssetMap<String, BlockBoundingBoxes>> {
    @Override
    @Nonnull
    public Packet generateInitPacket(@Nonnull IndexedLookupTableAssetMap<String, BlockBoundingBoxes> assetMap, @Nonnull Map<String, BlockBoundingBoxes> assets) {
        UpdateBlockHitboxes packet = new UpdateBlockHitboxes();
        packet.type = UpdateType.Init;
        Int2ObjectOpenHashMap<Hitbox[]> hitboxes = new Int2ObjectOpenHashMap<Hitbox[]>();
        for (Map.Entry<String, BlockBoundingBoxes> entry : assets.entrySet()) {
            String key = entry.getKey();
            int index = assetMap.getIndex(key);
            if (index == Integer.MIN_VALUE) {
                throw new IllegalArgumentException("Unknown key! " + key);
            }
            hitboxes.put(Integer.valueOf(index), entry.getValue().toPacket());
        }
        packet.blockBaseHitboxes = hitboxes;
        packet.maxId = assetMap.getNextIndex();
        return packet;
    }

    @Override
    @Nonnull
    public Packet generateUpdatePacket(@Nonnull IndexedLookupTableAssetMap<String, BlockBoundingBoxes> assetMap, @Nonnull Map<String, BlockBoundingBoxes> loadedAssets) {
        UpdateBlockHitboxes packet = new UpdateBlockHitboxes();
        packet.type = UpdateType.AddOrUpdate;
        Int2ObjectOpenHashMap<Hitbox[]> hitboxes = new Int2ObjectOpenHashMap<Hitbox[]>();
        for (Map.Entry<String, BlockBoundingBoxes> entry : loadedAssets.entrySet()) {
            String key = entry.getKey();
            int index = assetMap.getIndex(key);
            if (index == Integer.MIN_VALUE) {
                throw new IllegalArgumentException("Unknown key! " + key);
            }
            hitboxes.put(Integer.valueOf(index), entry.getValue().toPacket());
        }
        packet.blockBaseHitboxes = hitboxes;
        packet.maxId = assetMap.getNextIndex();
        return packet;
    }

    @Override
    @Nonnull
    public Packet generateRemovePacket(@Nonnull IndexedLookupTableAssetMap<String, BlockBoundingBoxes> assetMap, @Nonnull Set<String> removed) {
        UpdateBlockHitboxes packet = new UpdateBlockHitboxes();
        packet.type = UpdateType.Remove;
        Int2ObjectOpenHashMap<Hitbox[]> hitboxes = new Int2ObjectOpenHashMap<Hitbox[]>();
        for (String key : removed) {
            int index = assetMap.getIndex(key);
            if (index == Integer.MIN_VALUE) {
                throw new IllegalArgumentException("Unknown key! " + key);
            }
            hitboxes.put(Integer.valueOf(index), (Hitbox[])null);
        }
        packet.blockBaseHitboxes = hitboxes;
        return packet;
    }
}

