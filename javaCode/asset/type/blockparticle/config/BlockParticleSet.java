/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.type.blockparticle.config;

import com.hypixel.hytale.assetstore.AssetExtraInfo;
import com.hypixel.hytale.assetstore.AssetKeyValidator;
import com.hypixel.hytale.assetstore.AssetRegistry;
import com.hypixel.hytale.assetstore.AssetStore;
import com.hypixel.hytale.assetstore.codec.AssetBuilderCodec;
import com.hypixel.hytale.assetstore.map.DefaultAssetMap;
import com.hypixel.hytale.assetstore.map.JsonAssetWithMap;
import com.hypixel.hytale.codec.Codec;
import com.hypixel.hytale.codec.KeyedCodec;
import com.hypixel.hytale.codec.codecs.map.EnumMapCodec;
import com.hypixel.hytale.codec.schema.metadata.ui.UIDefaultCollapsedState;
import com.hypixel.hytale.codec.validation.ValidatorCache;
import com.hypixel.hytale.codec.validation.Validators;
import com.hypixel.hytale.protocol.BlockParticleEvent;
import com.hypixel.hytale.protocol.Color;
import com.hypixel.hytale.protocol.Direction;
import com.hypixel.hytale.protocol.Vector3f;
import com.hypixel.hytale.server.core.asset.type.particle.config.ParticleSystem;
import com.hypixel.hytale.server.core.codec.ProtocolCodecs;
import com.hypixel.hytale.server.core.io.NetworkSerializable;
import java.lang.ref.SoftReference;
import java.util.Map;
import javax.annotation.Nonnull;

public class BlockParticleSet
implements JsonAssetWithMap<String, DefaultAssetMap<String, BlockParticleSet>>,
NetworkSerializable<com.hypixel.hytale.protocol.BlockParticleSet> {
    public static final AssetBuilderCodec<String, BlockParticleSet> CODEC = ((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)((AssetBuilderCodec.Builder)AssetBuilderCodec.builder(BlockParticleSet.class, BlockParticleSet::new, Codec.STRING, (blockParticleSet, s) -> {
        blockParticleSet.id = s;
    }, blockParticleSet -> blockParticleSet.id, (asset, data) -> {
        asset.data = data;
    }, asset -> asset.data).documentation("Particle Systems that can be spawned in relation to block events.")).appendInherited(new KeyedCodec<Color>("Color", ProtocolCodecs.COLOR), (blockParticleSet, s) -> {
        blockParticleSet.color = s;
    }, blockParticleSet -> blockParticleSet.color, (blockParticleSet, parent) -> {
        blockParticleSet.color = parent.color;
    }).documentation("The colour used if none was specified in the particle settings.").add()).appendInherited(new KeyedCodec<Float>("Scale", Codec.FLOAT), (blockParticleSet, f) -> {
        blockParticleSet.scale = f.floatValue();
    }, blockParticleSet -> Float.valueOf(blockParticleSet.scale), (blockParticleSet, parent) -> {
        blockParticleSet.scale = parent.scale;
    }).documentation("The scale of the particle system.").add()).appendInherited(new KeyedCodec<Vector3f>("PositionOffset", ProtocolCodecs.VECTOR3F), (blockParticleSet, s) -> {
        blockParticleSet.positionOffset = s;
    }, blockParticleSet -> blockParticleSet.positionOffset, (blockParticleSet, parent) -> {
        blockParticleSet.positionOffset = parent.positionOffset;
    }).documentation("The position offset from the spawn position.").add()).appendInherited(new KeyedCodec<Direction>("RotationOffset", ProtocolCodecs.DIRECTION), (blockParticleSet, s) -> {
        blockParticleSet.rotationOffset = s;
    }, blockParticleSet -> blockParticleSet.rotationOffset, (blockParticleSet, parent) -> {
        blockParticleSet.rotationOffset = parent.rotationOffset;
    }).documentation("The rotation offset from the spawn rotation.").add()).appendInherited(new KeyedCodec("Particles", new EnumMapCodec<BlockParticleEvent, String>(BlockParticleEvent.class, Codec.STRING)), (blockParticleSet, s) -> {
        blockParticleSet.particleSystemIds = s;
    }, blockParticleSet -> blockParticleSet.particleSystemIds, (blockParticleSet, parent) -> {
        blockParticleSet.particleSystemIds = parent.particleSystemIds;
    }).addValidator(Validators.nonNull()).addValidator(ParticleSystem.VALIDATOR_CACHE.getMapValueValidator()).metadata(UIDefaultCollapsedState.UNCOLLAPSED).add()).build();
    private static AssetStore<String, BlockParticleSet, DefaultAssetMap<String, BlockParticleSet>> ASSET_STORE;
    public static final ValidatorCache<String> VALIDATOR_CACHE;
    protected AssetExtraInfo.Data data;
    protected String id;
    protected Color color;
    protected float scale = 1.0f;
    protected Vector3f positionOffset;
    protected Direction rotationOffset;
    protected Map<BlockParticleEvent, String> particleSystemIds;
    private SoftReference<com.hypixel.hytale.protocol.BlockParticleSet> cachedPacket;

    public static AssetStore<String, BlockParticleSet, DefaultAssetMap<String, BlockParticleSet>> getAssetStore() {
        if (ASSET_STORE == null) {
            ASSET_STORE = AssetRegistry.getAssetStore(BlockParticleSet.class);
        }
        return ASSET_STORE;
    }

    public static DefaultAssetMap<String, BlockParticleSet> getAssetMap() {
        return BlockParticleSet.getAssetStore().getAssetMap();
    }

    public BlockParticleSet(String id, Color color, float scale, Vector3f positionOffset, Direction rotationOffset, Map<BlockParticleEvent, String> particleSystemIds) {
        this.id = id;
        this.color = color;
        this.scale = scale;
        this.positionOffset = positionOffset;
        this.rotationOffset = rotationOffset;
        this.particleSystemIds = particleSystemIds;
    }

    protected BlockParticleSet() {
    }

    @Override
    @Nonnull
    public com.hypixel.hytale.protocol.BlockParticleSet toPacket() {
        com.hypixel.hytale.protocol.BlockParticleSet cached;
        com.hypixel.hytale.protocol.BlockParticleSet blockParticleSet = cached = this.cachedPacket == null ? null : this.cachedPacket.get();
        if (cached != null) {
            return cached;
        }
        com.hypixel.hytale.protocol.BlockParticleSet packet = new com.hypixel.hytale.protocol.BlockParticleSet();
        packet.id = this.id;
        packet.color = this.color;
        packet.scale = this.scale;
        packet.positionOffset = this.positionOffset;
        packet.rotationOffset = this.rotationOffset;
        packet.particleSystemIds = this.particleSystemIds;
        this.cachedPacket = new SoftReference<com.hypixel.hytale.protocol.BlockParticleSet>(packet);
        return packet;
    }

    @Override
    public String getId() {
        return this.id;
    }

    public Color getColor() {
        return this.color;
    }

    public float getScale() {
        return this.scale;
    }

    public Vector3f getPositionOffset() {
        return this.positionOffset;
    }

    public Direction getRotationOffset() {
        return this.rotationOffset;
    }

    public Map<BlockParticleEvent, String> getParticleSystemIds() {
        return this.particleSystemIds;
    }

    @Nonnull
    public String toString() {
        return "BlockParticleSet{id='" + this.id + "', color=" + String.valueOf(this.color) + ", scale=" + this.scale + ", positionOffset=" + String.valueOf(this.positionOffset) + ", rotationOffset=" + String.valueOf(this.rotationOffset) + ", particleSystemIds=" + String.valueOf(this.particleSystemIds) + "}";
    }

    static {
        VALIDATOR_CACHE = new ValidatorCache(new AssetKeyValidator(BlockParticleSet::getAssetStore));
    }
}

