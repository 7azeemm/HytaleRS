/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.codec;

import com.hypixel.hytale.assetstore.AssetExtraInfo;
import com.hypixel.hytale.assetstore.JsonAsset;
import com.hypixel.hytale.assetstore.codec.AssetBuilderCodec;
import com.hypixel.hytale.assetstore.codec.AssetCodec;
import com.hypixel.hytale.codec.Codec;
import com.hypixel.hytale.codec.ExtraInfo;
import com.hypixel.hytale.codec.KeyedCodec;
import com.hypixel.hytale.codec.builder.BuilderCodec;
import com.hypixel.hytale.codec.exception.CodecException;
import com.hypixel.hytale.codec.lookup.ACodecMapCodec;
import com.hypixel.hytale.codec.lookup.Priority;
import com.hypixel.hytale.codec.lookup.StringCodecMapCodec;
import com.hypixel.hytale.codec.schema.SchemaContext;
import com.hypixel.hytale.codec.schema.config.ObjectSchema;
import com.hypixel.hytale.codec.schema.config.Schema;
import com.hypixel.hytale.codec.util.RawJsonReader;
import java.io.IOException;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.bson.BsonDocument;
import org.bson.BsonValue;

public class AssetCodecMapCodec<K, T extends JsonAsset<K>>
extends StringCodecMapCodec<T, AssetBuilderCodec<K, T>>
implements AssetCodec<K, T> {
    @Nonnull
    protected final KeyedCodec<K> idCodec;
    @Nonnull
    protected final KeyedCodec<K> parentCodec;
    protected final BiConsumer<T, K> idSetter;
    protected final Function<T, K> idGetter;
    protected final BiConsumer<T, AssetExtraInfo.Data> dataSetter;
    protected final Function<T, AssetExtraInfo.Data> dataGetter;

    public AssetCodecMapCodec(Codec<K> idCodec, BiConsumer<T, K> idSetter, Function<T, K> idGetter, BiConsumer<T, AssetExtraInfo.Data> dataSetter, Function<T, AssetExtraInfo.Data> dataGetter) {
        super("Type");
        this.idCodec = new KeyedCodec<K>("Id", idCodec);
        this.parentCodec = new KeyedCodec<K>("Parent", idCodec);
        this.idSetter = idSetter;
        this.idGetter = idGetter;
        this.dataSetter = dataSetter;
        this.dataGetter = dataGetter;
    }

    public AssetCodecMapCodec(String key, Codec<K> idCodec, BiConsumer<T, K> idSetter, Function<T, K> idGetter, BiConsumer<T, AssetExtraInfo.Data> dataSetter, Function<T, AssetExtraInfo.Data> dataGetter) {
        super(key);
        this.idCodec = new KeyedCodec<K>("Id", idCodec);
        this.parentCodec = new KeyedCodec<K>("Parent", idCodec);
        this.idSetter = idSetter;
        this.idGetter = idGetter;
        this.dataSetter = dataSetter;
        this.dataGetter = dataGetter;
    }

    public AssetCodecMapCodec(Codec<K> idCodec, BiConsumer<T, K> idSetter, Function<T, K> idGetter, BiConsumer<T, AssetExtraInfo.Data> dataSetter, Function<T, AssetExtraInfo.Data> dataGetter, boolean allowDefault) {
        super("Type", allowDefault);
        this.idCodec = new KeyedCodec<K>("Id", idCodec);
        this.parentCodec = new KeyedCodec<K>("Parent", idCodec);
        this.idSetter = idSetter;
        this.idGetter = idGetter;
        this.dataSetter = dataSetter;
        this.dataGetter = dataGetter;
    }

    public AssetCodecMapCodec(String key, Codec<K> idCodec, BiConsumer<T, K> idSetter, Function<T, K> idGetter, BiConsumer<T, AssetExtraInfo.Data> dataSetter, Function<T, AssetExtraInfo.Data> dataGetter, boolean allowDefault) {
        super(key, allowDefault);
        this.idCodec = new KeyedCodec<K>("Id", idCodec);
        this.parentCodec = new KeyedCodec<K>("Parent", idCodec);
        this.idSetter = idSetter;
        this.idGetter = idGetter;
        this.dataSetter = dataSetter;
        this.dataGetter = dataGetter;
    }

    @Override
    @Nonnull
    public KeyedCodec<K> getKeyCodec() {
        return this.idCodec;
    }

    @Override
    @Nonnull
    public KeyedCodec<K> getParentCodec() {
        return this.parentCodec;
    }

    @Override
    public AssetExtraInfo.Data getData(T t) {
        return this.dataGetter.apply(t);
    }

    @Nonnull
    public AssetCodecMapCodec<K, T> register(@Nonnull String id, Class<? extends T> aClass, BuilderCodec<? extends T> codec) {
        return this.register(Priority.NORMAL, id, aClass, codec);
    }

    @Override
    @Nonnull
    public AssetCodecMapCodec<K, T> register(@Nonnull Priority priority, @Nonnull String id, Class<? extends T> aClass, BuilderCodec<? extends T> codec) {
        BuilderCodec<? extends T> builderCodec = codec;
        AssetBuilderCodec<K, ? extends T> assetCodec = AssetBuilderCodec.wrap(builderCodec, this.idCodec.getChildCodec(), this.idSetter, this.idGetter, this.dataSetter, this.dataGetter);
        super.register(priority, id, aClass, assetCodec);
        return this;
    }

    @Override
    public T decodeAndInherit(@Nonnull BsonDocument document, T parent, ExtraInfo extraInfo) {
        BsonValue id = document.get(this.key);
        AssetBuilderCodec codec = (AssetBuilderCodec)this.idToCodec.get(id == null ? null : id.asString().getValue());
        if (codec == null) {
            AssetBuilderCodec defaultCodec = (AssetBuilderCodec)this.getDefaultCodec();
            if (defaultCodec == null) {
                throw new ACodecMapCodec.UnknownIdException("No codec registered with for '" + this.key + "': " + String.valueOf(id));
            }
            return (T)((JsonAsset)defaultCodec.decodeAndInherit(document, parent, extraInfo));
        }
        return (T)((JsonAsset)codec.decodeAndInherit(document, parent, extraInfo));
    }

    @Override
    public void decodeAndInherit(@Nonnull BsonDocument document, T t, T parent, ExtraInfo extraInfo) {
        BsonValue id = document.get(this.key);
        AssetBuilderCodec codec = (AssetBuilderCodec)this.idToCodec.get(id == null ? null : id.asString().getValue());
        if (codec == null) {
            AssetBuilderCodec defaultCodec = (AssetBuilderCodec)this.getDefaultCodec();
            if (defaultCodec == null) {
                throw new ACodecMapCodec.UnknownIdException("No codec registered with for '" + this.key + "': " + String.valueOf(id));
            }
            defaultCodec.decodeAndInherit(document, t, parent, extraInfo);
            return;
        }
        codec.decodeAndInherit(document, t, parent, extraInfo);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    public T decodeAndInheritJson(@Nonnull RawJsonReader reader, @Nullable T parent, @Nonnull ExtraInfo extraInfo) throws IOException {
        reader.mark();
        String id = null;
        if (RawJsonReader.seekToKey(reader, this.key)) {
            id = reader.readString();
        } else if (parent != null) {
            id = (String)this.getIdFor(parent.getClass());
        }
        reader.reset();
        extraInfo.ignoreUnusedKey(this.key);
        try {
            AssetBuilderCodec codec;
            AssetBuilderCodec assetBuilderCodec = codec = id == null ? null : (AssetBuilderCodec)this.idToCodec.get(id);
            if (codec == null) {
                AssetBuilderCodec defaultCodec = (AssetBuilderCodec)this.getDefaultCodec();
                if (defaultCodec == null) {
                    throw new ACodecMapCodec.UnknownIdException("No codec registered with for '" + this.key + "': " + id);
                }
                JsonAsset jsonAsset = (JsonAsset)defaultCodec.decodeAndInheritJson(reader, parent, extraInfo);
                return (T)jsonAsset;
            }
            JsonAsset jsonAsset = (JsonAsset)codec.decodeAndInheritJson(reader, parent, extraInfo);
            return (T)jsonAsset;
        }
        finally {
            extraInfo.popIgnoredUnusedKey();
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    public void decodeAndInheritJson(@Nonnull RawJsonReader reader, T t, @Nullable T parent, @Nonnull ExtraInfo extraInfo) throws IOException {
        reader.mark();
        String id = null;
        if (RawJsonReader.seekToKey(reader, this.key)) {
            id = reader.readString();
        } else if (parent != null) {
            id = (String)this.getIdFor(parent.getClass());
        }
        reader.reset();
        extraInfo.ignoreUnusedKey(this.key);
        try {
            AssetBuilderCodec codec;
            AssetBuilderCodec assetBuilderCodec = codec = id == null ? null : (AssetBuilderCodec)this.idToCodec.get(id);
            if (codec == null) {
                AssetBuilderCodec defaultCodec = (AssetBuilderCodec)this.getDefaultCodec();
                if (defaultCodec == null) {
                    throw new ACodecMapCodec.UnknownIdException("No codec registered with for '" + this.key + "': " + id);
                }
                defaultCodec.decodeAndInheritJson(reader, t, parent, extraInfo);
                return;
            }
            codec.decodeAndInheritJson(reader, t, parent, extraInfo);
        }
        finally {
            extraInfo.popIgnoredUnusedKey();
        }
    }

    @Override
    public T decodeJsonAsset(@Nonnull RawJsonReader reader, @Nonnull AssetExtraInfo<K> extraInfo) throws IOException {
        return this.decodeAndInheritJsonAsset(reader, null, extraInfo);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    public T decodeAndInheritJsonAsset(@Nonnull RawJsonReader reader, @Nullable T parent, @Nonnull AssetExtraInfo<K> extraInfo) throws IOException {
        reader.mark();
        String id = null;
        if (RawJsonReader.seekToKey(reader, this.key)) {
            id = reader.readString();
        } else if (parent != null) {
            id = (String)this.getIdFor(parent.getClass());
        }
        reader.reset();
        extraInfo.ignoreUnusedKey(this.key);
        try {
            Supplier supplier;
            AssetBuilderCodec codec;
            AssetBuilderCodec assetBuilderCodec = codec = id == null ? null : (AssetBuilderCodec)this.idToCodec.get(id);
            if (codec == null) {
                AssetBuilderCodec defaultCodec = (AssetBuilderCodec)this.getDefaultCodec();
                if (defaultCodec == null) {
                    throw new ACodecMapCodec.UnknownIdException("No codec registered with for '" + this.key + "': " + id);
                }
                codec = defaultCodec;
            }
            if ((supplier = codec.getSupplier()) == null) {
                throw new CodecException("This BuilderCodec is for an abstract or direct codec. To use this codec you must specify an existing object to decode into.");
            }
            JsonAsset t = (JsonAsset)supplier.get();
            this.dataSetter.accept(t, extraInfo.getData());
            if (parent != null) {
                codec.inherit(t, parent, extraInfo);
            }
            codec.decodeAndInheritJson0(reader, t, parent, extraInfo);
            this.idSetter.accept(t, extraInfo.getKey());
            codec.afterDecodeAndValidate(t, extraInfo);
            JsonAsset jsonAsset = t;
            return (T)jsonAsset;
        }
        finally {
            extraInfo.popIgnoredUnusedKey();
        }
    }

    @Override
    @Nonnull
    public Schema toSchema(@Nonnull SchemaContext context) {
        Schema schema = super.toSchema(context);
        schema.getHytaleSchemaTypeField().setParentPropertyKey(this.parentCodec.getKey());
        return schema;
    }

    @Override
    protected void mutateChildSchema(String key, @Nonnull SchemaContext context, BuilderCodec<? extends T> c, @Nonnull ObjectSchema objectSchema) {
        super.mutateChildSchema(key, context, c, objectSchema);
        AssetBuilderCodec def = (AssetBuilderCodec)this.getDefaultCodec();
        if (!this.allowDefault || def != c) {
            Schema idField = new Schema();
            idField.setRequired(this.key);
            Schema parentField = new Schema();
            parentField.setRequired(this.parentCodec.getKey());
            AssetBuilderCodec bc = (AssetBuilderCodec)c;
            Schema parentSchema = objectSchema.getProperties().get(bc.getParentCodec().getKey());
            if (parentSchema != null) {
                Schema.InheritSettings settings = parentSchema.getHytaleParent();
                settings.setMapKey(this.key);
                settings.setMapKeyValue(key);
                objectSchema.setOneOf(idField, parentField);
            }
        }
    }
}

