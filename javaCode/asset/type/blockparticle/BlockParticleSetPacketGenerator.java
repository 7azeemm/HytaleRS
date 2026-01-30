/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.type.blockparticle;

import com.hypixel.hytale.assetstore.map.DefaultAssetMap;
import com.hypixel.hytale.protocol.Packet;
import com.hypixel.hytale.protocol.UpdateType;
import com.hypixel.hytale.protocol.packets.assets.UpdateBlockParticleSets;
import com.hypixel.hytale.server.core.asset.packet.DefaultAssetPacketGenerator;
import com.hypixel.hytale.server.core.asset.type.blockparticle.config.BlockParticleSet;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

public class BlockParticleSetPacketGenerator
extends DefaultAssetPacketGenerator<String, BlockParticleSet> {
    @Override
    @Nonnull
    public Packet generateInitPacket(DefaultAssetMap<String, BlockParticleSet> assetMap, @Nonnull Map<String, BlockParticleSet> assets) {
        UpdateBlockParticleSets packet = new UpdateBlockParticleSets();
        packet.type = UpdateType.Init;
        packet.blockParticleSets = new Object2ObjectOpenHashMap<String, com.hypixel.hytale.protocol.BlockParticleSet>();
        for (Map.Entry<String, BlockParticleSet> entry : assets.entrySet()) {
            packet.blockParticleSets.put(entry.getKey(), entry.getValue().toPacket());
        }
        return packet;
    }

    @Override
    @Nonnull
    public Packet generateUpdatePacket(@Nonnull Map<String, BlockParticleSet> loadedAssets) {
        UpdateBlockParticleSets packet = new UpdateBlockParticleSets();
        packet.type = UpdateType.AddOrUpdate;
        packet.blockParticleSets = new Object2ObjectOpenHashMap<String, com.hypixel.hytale.protocol.BlockParticleSet>();
        for (Map.Entry<String, BlockParticleSet> entry : loadedAssets.entrySet()) {
            packet.blockParticleSets.put(entry.getKey(), entry.getValue().toPacket());
        }
        return packet;
    }

    @Override
    @Nonnull
    public Packet generateRemovePacket(@Nonnull Set<String> removed) {
        UpdateBlockParticleSets packet = new UpdateBlockParticleSets();
        packet.type = UpdateType.Remove;
        packet.blockParticleSets = new Object2ObjectOpenHashMap<String, com.hypixel.hytale.protocol.BlockParticleSet>();
        for (String key : removed) {
            packet.blockParticleSets.put(key, null);
        }
        return packet;
    }
}

