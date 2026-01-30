/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore;

import com.hypixel.hytale.assetstore.AssetValidationResults;
import com.hypixel.hytale.assetstore.JsonAsset;
import com.hypixel.hytale.codec.ExtraInfo;
import com.hypixel.hytale.codec.validation.ValidationResults;
import javax.annotation.Nonnull;

public class MissingAssetException
extends RuntimeException {
    private String field;
    private Class<? extends JsonAsset> assetType;
    private Object assetId;

    public MissingAssetException(String field, @Nonnull Class<? extends JsonAsset> assetType, Object assetId) {
        super("Missing asset '" + String.valueOf(assetId) + "' of type " + assetType.getSimpleName() + " for field '" + field + "'!");
        this.field = field;
        this.assetType = assetType;
        this.assetId = assetId;
    }

    public MissingAssetException(String field, @Nonnull Class<? extends JsonAsset> assetType, Object assetId, String extra) {
        super("Missing asset '" + String.valueOf(assetId) + "' of type " + assetType.getSimpleName() + " for field '" + field + "'! " + extra);
        this.field = field;
        this.assetType = assetType;
        this.assetId = assetId;
    }

    public String getField() {
        return this.field;
    }

    public Class<? extends JsonAsset> getAssetType() {
        return this.assetType;
    }

    public Object getAssetId() {
        return this.assetId;
    }

    public static void handle(@Nonnull ExtraInfo extraInfo, String field, @Nonnull Class<? extends JsonAsset> assetType, Object assetId) {
        ValidationResults validationResults = extraInfo.getValidationResults();
        if (!(validationResults instanceof AssetValidationResults)) {
            throw new MissingAssetException(field, assetType, assetId);
        }
        ((AssetValidationResults)validationResults).handleMissingAsset(field, assetType, assetId);
    }

    public static void handle(@Nonnull ExtraInfo extraInfo, String field, @Nonnull Class<? extends JsonAsset> assetType, Object assetId, String extra) {
        ValidationResults validationResults = extraInfo.getValidationResults();
        if (!(validationResults instanceof AssetValidationResults)) {
            throw new MissingAssetException(field, assetType, assetId, extra);
        }
        ((AssetValidationResults)validationResults).handleMissingAsset(field, assetType, assetId, extra);
    }
}

