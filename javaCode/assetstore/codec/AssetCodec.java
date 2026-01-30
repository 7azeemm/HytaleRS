/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.codec;

import com.hypixel.hytale.assetstore.AssetExtraInfo;
import com.hypixel.hytale.assetstore.JsonAsset;
import com.hypixel.hytale.codec.InheritCodec;
import com.hypixel.hytale.codec.KeyedCodec;
import com.hypixel.hytale.codec.util.RawJsonReader;
import com.hypixel.hytale.codec.validation.ValidatableCodec;
import java.io.IOException;
import javax.annotation.Nullable;

public interface AssetCodec<K, T extends JsonAsset<K>>
extends InheritCodec<T>,
ValidatableCodec<T> {
    public KeyedCodec<K> getKeyCodec();

    public KeyedCodec<K> getParentCodec();

    @Nullable
    public AssetExtraInfo.Data getData(T var1);

    public T decodeJsonAsset(RawJsonReader var1, AssetExtraInfo<K> var2) throws IOException;

    public T decodeAndInheritJsonAsset(RawJsonReader var1, T var2, AssetExtraInfo<K> var3) throws IOException;
}

