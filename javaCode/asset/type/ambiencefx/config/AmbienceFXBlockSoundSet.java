/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.type.ambiencefx.config;

import com.hypixel.hytale.codec.Codec;
import com.hypixel.hytale.codec.KeyedCodec;
import com.hypixel.hytale.codec.builder.BuilderCodec;
import com.hypixel.hytale.codec.validation.Validators;
import com.hypixel.hytale.protocol.Rangef;
import com.hypixel.hytale.server.core.asset.type.blocksound.config.BlockSoundSet;
import com.hypixel.hytale.server.core.codec.ProtocolCodecs;
import com.hypixel.hytale.server.core.io.NetworkSerializable;
import javax.annotation.Nonnull;

public class AmbienceFXBlockSoundSet
implements NetworkSerializable<com.hypixel.hytale.protocol.AmbienceFXBlockSoundSet> {
    public static final BuilderCodec<AmbienceFXBlockSoundSet> CODEC = ((BuilderCodec.Builder)((BuilderCodec.Builder)((BuilderCodec.Builder)BuilderCodec.builder(AmbienceFXBlockSoundSet.class, AmbienceFXBlockSoundSet::new).append(new KeyedCodec<String>("BlockSoundSetId", Codec.STRING), (ambienceFXBlockSoundSet, s) -> {
        ambienceFXBlockSoundSet.blockSoundSetId = s;
    }, ambienceFXBlockSoundSet -> ambienceFXBlockSoundSet.blockSoundSetId).addValidator(Validators.nonNull()).addValidator(BlockSoundSet.VALIDATOR_CACHE.getValidator()).add()).addField(new KeyedCodec<Rangef>("Percent", ProtocolCodecs.RANGEF), (ambienceFXBlockSoundSet, o) -> {
        ambienceFXBlockSoundSet.percent = o;
    }, ambienceFXBlockSoundSet -> ambienceFXBlockSoundSet.percent)).afterDecode(AmbienceFXBlockSoundSet::processConfig)).build();
    public static final Rangef DEFAULT_PERCENT = new Rangef(0.0f, 0.0f);
    protected String blockSoundSetId;
    protected transient int blockSoundSetIndex;
    protected Rangef percent = DEFAULT_PERCENT;

    public AmbienceFXBlockSoundSet(String blockSoundSetId, Rangef percent) {
        this.blockSoundSetId = blockSoundSetId;
        this.percent = percent;
    }

    protected AmbienceFXBlockSoundSet() {
    }

    @Override
    @Nonnull
    public com.hypixel.hytale.protocol.AmbienceFXBlockSoundSet toPacket() {
        com.hypixel.hytale.protocol.AmbienceFXBlockSoundSet packet = new com.hypixel.hytale.protocol.AmbienceFXBlockSoundSet();
        packet.blockSoundSetIndex = this.blockSoundSetIndex;
        packet.percent = this.percent;
        return packet;
    }

    public String getBlockSoundSetId() {
        return this.blockSoundSetId;
    }

    public Rangef getPercent() {
        return this.percent;
    }

    protected void processConfig() {
        this.blockSoundSetIndex = BlockSoundSet.getAssetMap().getIndex(this.blockSoundSetId);
    }

    @Nonnull
    public String toString() {
        return "AmbienceFXBlockSoundSet{blockSoundSetId='" + this.blockSoundSetId + "'blockSoundSetIndex='" + this.blockSoundSetIndex + "', percent=" + String.valueOf(this.percent) + "}";
    }
}

