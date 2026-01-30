/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.codec;

import com.hypixel.hytale.assetstore.AssetExtraInfo;
import com.hypixel.hytale.assetstore.JsonAsset;
import com.hypixel.hytale.assetstore.codec.AssetCodec;
import com.hypixel.hytale.codec.Codec;
import com.hypixel.hytale.codec.KeyedCodec;
import com.hypixel.hytale.codec.builder.BuilderCodec;
import com.hypixel.hytale.codec.codecs.map.MapCodec;
import com.hypixel.hytale.codec.schema.SchemaContext;
import com.hypixel.hytale.codec.schema.config.ObjectSchema;
import com.hypixel.hytale.codec.schema.config.Schema;
import com.hypixel.hytale.codec.util.RawJsonReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class AssetBuilderCodec<K, T extends JsonAsset<K>>
extends BuilderCodec<T>
implements AssetCodec<K, T> {
    public static final KeyedCodec<Map<String, String[]>> TAGS_CODEC = new KeyedCodec("Tags", new MapCodec<T[], HashMap>(Codec.STRING_ARRAY, HashMap::new));
    private static final String TAG_DOCUMENTATION = "Tags are a general way to describe an asset that can be interpreted by other systems in a way they see fit.\n\nFor example you could tag something with a **Material** tag with the values **Solid** and **Stone**, And another single tag **Ore**.\n\nTags will be expanded into a single list of tags automatically. Using the above example with **Material** and **Ore** the end result would be the following list of tags: **Ore**, **Material**, **Solid**, **Stone**, **Material=Solid** and **Material=Stone**.";
    @Nonnull
    protected final KeyedCodec<K> idCodec;
    @Nonnull
    protected final KeyedCodec<K> parentCodec;
    protected final BiConsumer<T, K> idSetter;
    protected final BiConsumer<T, AssetExtraInfo.Data> dataSetter;
    @Nonnull
    protected final Function<T, AssetExtraInfo.Data> dataGetter;

    protected AssetBuilderCodec(@Nonnull Builder<K, T> builder) {
        super(builder);
        this.idCodec = builder.idCodec;
        this.parentCodec = new KeyedCodec<K>("Parent", this.idCodec.getChildCodec());
        this.idSetter = builder.idSetter;
        this.dataSetter = builder.dataSetter;
        this.dataGetter = builder.dataGetter;
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

    @Override
    public T decodeJsonAsset(@Nonnull RawJsonReader reader, @Nonnull AssetExtraInfo<K> extraInfo) throws IOException {
        return this.decodeAndInheritJsonAsset(reader, null, extraInfo);
    }

    @Override
    public T decodeAndInheritJsonAsset(@Nonnull RawJsonReader reader, @Nullable T parent, @Nonnull AssetExtraInfo<K> extraInfo) throws IOException {
        JsonAsset t = (JsonAsset)this.supplier.get();
        this.dataSetter.accept(t, extraInfo.getData());
        if (parent != null) {
            this.inherit(t, parent, extraInfo);
        }
        this.decodeAndInheritJson0(reader, t, parent, extraInfo);
        this.idSetter.accept(t, extraInfo.getKey());
        this.afterDecodeAndValidate(t, extraInfo);
        return (T)t;
    }

    @Override
    @Nonnull
    public ObjectSchema toSchema(@Nonnull SchemaContext context) {
        return this.toSchema(context, (T)((JsonAsset)this.supplier.get()));
    }

    @Override
    @Nonnull
    public ObjectSchema toSchema(@Nonnull SchemaContext context, @Nullable T def) {
        Schema schema = super.toSchema(context, (Object)def);
        KeyedCodec<K> parent = this.getParentCodec();
        Schema parentSchema = parent.getChildCodec().toSchema(context);
        parentSchema.setMarkdownDescription("When set this asset will inherit properties from the named asset.\n\nWhen inheriting from another **" + this.tClass.getSimpleName() + "** most properties will simply be copied from the parent asset to this asset. In the case where both child and parent provide a field the child field will simply replace the value provided by the parent, in the case of nested structures this will apply to the fields within the structure. In some cases the field may decide to act differently, for example: by merging the parent and child fields together.");
        Class rootClass = this.tClass;
        BuilderCodec rootCodec = this;
        while (rootCodec.getParent() != null) {
            rootCodec = rootCodec.getParent();
            rootClass = rootCodec.getInnerClass();
        }
        parentSchema.setHytaleParent(new Schema.InheritSettings(rootClass.getSimpleName()));
        LinkedHashMap<String, Schema> props = new LinkedHashMap<String, Schema>();
        props.put(parent.getKey(), parentSchema);
        props.putAll(((ObjectSchema)schema).getProperties());
        ((ObjectSchema)schema).setProperties(props);
        return schema;
    }

    @Nonnull
    public static <K, T extends JsonAsset<K>> Builder<K, T> builder(Class<T> tClass, Supplier<T> supplier, Codec<K> idCodec, BiConsumer<T, K> idSetter, Function<T, K> idGetter, BiConsumer<T, AssetExtraInfo.Data> dataSetter, @Nonnull Function<T, AssetExtraInfo.Data> dataGetter) {
        return new Builder<K, T>(tClass, supplier, idCodec, idSetter, idGetter, dataSetter, dataGetter);
    }

    @Nonnull
    public static <K, T extends JsonAsset<K>> Builder<K, T> builder(Class<T> tClass, Supplier<T> supplier, BuilderCodec<? super T> parentCodec, Codec<K> idCodec, BiConsumer<T, K> idSetter, Function<T, K> idGetter, BiConsumer<T, AssetExtraInfo.Data> dataSetter, @Nonnull Function<T, AssetExtraInfo.Data> dataGetter) {
        return new Builder<K, T>(tClass, supplier, parentCodec, idCodec, idSetter, idGetter, dataSetter, dataGetter);
    }

    @Nonnull
    public static <K, T extends JsonAsset<K>> AssetBuilderCodec<K, T> wrap(@Nonnull BuilderCodec<T> codec, Codec<K> idCodec, BiConsumer<T, K> idSetter, Function<T, K> idGetter, BiConsumer<T, AssetExtraInfo.Data> dataSetter, @Nonnull Function<T, AssetExtraInfo.Data> dataGetter) {
        return ((Builder)AssetBuilderCodec.builder(codec.getInnerClass(), codec.getSupplier(), codec, idCodec, idSetter, idGetter, dataSetter, dataGetter).documentation(codec.getDocumentation())).build();
    }

    public static class Builder<K, T extends JsonAsset<K>>
    extends BuilderCodec.BuilderBase<T, Builder<K, T>> {
        @Nonnull
        protected final KeyedCodec<K> idCodec;
        protected final BiConsumer<T, K> idSetter;
        protected final BiConsumer<T, AssetExtraInfo.Data> dataSetter;
        @Nonnull
        protected final Function<T, AssetExtraInfo.Data> dataGetter;

        public Builder(Class<T> tClass, Supplier<T> supplier, Codec<K> idCodec, BiConsumer<T, K> idSetter, Function<T, K> idGetter, BiConsumer<T, AssetExtraInfo.Data> dataSetter, @Nonnull Function<T, AssetExtraInfo.Data> dataGetter) {
            super(tClass, supplier);
            this.idCodec = new KeyedCodec<K>("Id", idCodec);
            this.idSetter = idSetter;
            this.dataSetter = dataSetter;
            this.dataGetter = dataGetter;
            this.appendInherited(TAGS_CODEC, (T t, FieldType tags) -> ((AssetExtraInfo.Data)dataGetter.apply(t)).putTags((Map<String, String[]>)tags), (T t) -> {
                AssetExtraInfo.Data data = (AssetExtraInfo.Data)dataGetter.apply(t);
                return data != null ? data.getRawTags() : null;
            }, (T t, T parent) -> {
                AssetExtraInfo.Data data = (AssetExtraInfo.Data)dataGetter.apply(t);
                AssetExtraInfo.Data parentData = (AssetExtraInfo.Data)dataGetter.apply(parent);
                if (data != null && parentData != null) {
                    data.putTags(parentData.getRawTags());
                }
            }).documentation(AssetBuilderCodec.TAG_DOCUMENTATION).add();
        }

        public Builder(Class<T> tClass, Supplier<T> supplier, BuilderCodec<? super T> parentCodec, Codec<K> idCodec, BiConsumer<T, K> idSetter, Function<T, K> idGetter, BiConsumer<T, AssetExtraInfo.Data> dataSetter, @Nonnull Function<T, AssetExtraInfo.Data> dataGetter) {
            super(tClass, supplier, parentCodec);
            this.idCodec = new KeyedCodec<K>("Id", idCodec);
            this.idSetter = idSetter;
            this.dataSetter = dataSetter;
            this.dataGetter = dataGetter;
            this.appendInherited(TAGS_CODEC, (T t, FieldType tags) -> ((AssetExtraInfo.Data)dataGetter.apply(t)).putTags((Map<String, String[]>)tags), (T t) -> {
                AssetExtraInfo.Data data = (AssetExtraInfo.Data)dataGetter.apply(t);
                return data != null ? data.getRawTags() : null;
            }, (T t, T parent) -> {
                AssetExtraInfo.Data data = (AssetExtraInfo.Data)dataGetter.apply(t);
                AssetExtraInfo.Data parentData = (AssetExtraInfo.Data)dataGetter.apply(parent);
                if (data != null && parentData != null) {
                    data.putTags(parentData.getRawTags());
                }
            }).documentation(AssetBuilderCodec.TAG_DOCUMENTATION).add();
        }

        @Nonnull
        public AssetBuilderCodec<K, T> build() {
            return new AssetBuilderCodec(this);
        }
    }
}

