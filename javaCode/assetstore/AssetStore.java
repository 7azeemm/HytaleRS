/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore;

import com.hypixel.hytale.assetstore.AssetExtraInfo;
import com.hypixel.hytale.assetstore.AssetHolder;
import com.hypixel.hytale.assetstore.AssetKeyValidator;
import com.hypixel.hytale.assetstore.AssetLoadResult;
import com.hypixel.hytale.assetstore.AssetMap;
import com.hypixel.hytale.assetstore.AssetPack;
import com.hypixel.hytale.assetstore.AssetReferences;
import com.hypixel.hytale.assetstore.AssetRegistry;
import com.hypixel.hytale.assetstore.AssetUpdateQuery;
import com.hypixel.hytale.assetstore.AssetValidationResults;
import com.hypixel.hytale.assetstore.DecodedAsset;
import com.hypixel.hytale.assetstore.JsonAsset;
import com.hypixel.hytale.assetstore.RawAsset;
import com.hypixel.hytale.assetstore.codec.AssetCodec;
import com.hypixel.hytale.assetstore.codec.ContainedAssetCodec;
import com.hypixel.hytale.assetstore.event.AssetsEvent;
import com.hypixel.hytale.assetstore.event.GenerateAssetsEvent;
import com.hypixel.hytale.assetstore.event.LoadedAssetsEvent;
import com.hypixel.hytale.assetstore.event.RemovedAssetsEvent;
import com.hypixel.hytale.assetstore.map.JsonAssetWithMap;
import com.hypixel.hytale.codec.Codec;
import com.hypixel.hytale.codec.ExtraInfo;
import com.hypixel.hytale.codec.KeyedCodec;
import com.hypixel.hytale.codec.builder.BuilderCodec;
import com.hypixel.hytale.codec.builder.BuilderField;
import com.hypixel.hytale.codec.exception.CodecException;
import com.hypixel.hytale.codec.exception.CodecValidationException;
import com.hypixel.hytale.codec.util.RawJsonReader;
import com.hypixel.hytale.codec.validation.ValidationResults;
import com.hypixel.hytale.codec.validation.Validator;
import com.hypixel.hytale.codec.validation.validator.ArrayValidator;
import com.hypixel.hytale.codec.validation.validator.MapKeyValidator;
import com.hypixel.hytale.codec.validation.validator.MapValueValidator;
import com.hypixel.hytale.common.util.FormatUtil;
import com.hypixel.hytale.common.util.StringUtil;
import com.hypixel.hytale.event.IEventBus;
import com.hypixel.hytale.event.IEventDispatcher;
import com.hypixel.hytale.logger.HytaleLogger;
import com.hypixel.hytale.logger.backend.HytaleLoggerBackend;
import com.hypixel.hytale.logger.sentry.SkipSentryException;
import com.hypixel.hytale.logger.util.GithubMessageUtil;
import com.hypixel.hytale.sneakythrow.SneakyThrow;
import it.unimi.dsi.fastutil.objects.Object2ObjectLinkedOpenHashMap;
import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.bson.BsonDocument;
import org.bson.BsonString;
import org.bson.BsonValue;

public abstract class AssetStore<K, T extends JsonAssetWithMap<K, M>, M extends AssetMap<K, T>> {
    public static boolean DISABLE_ASSET_COMPARE = true;
    @Nonnull
    protected final HytaleLogger logger;
    @Nonnull
    protected final Class<K> kClass;
    @Nonnull
    protected final Class<T> tClass;
    protected final String path;
    @Nonnull
    protected final String extension;
    protected final AssetCodec<K, T> codec;
    protected final Function<T, K> keyFunction;
    @Nonnull
    protected final Set<Class<? extends JsonAsset<?>>> loadsAfter;
    @Nonnull
    protected final Set<Class<? extends JsonAsset<?>>> unmodifiableLoadsAfter;
    @Nonnull
    protected final Set<Class<? extends JsonAsset<?>>> loadsBefore;
    protected final M assetMap;
    protected final Function<K, T> replaceOnRemove;
    @Nonnull
    protected final Predicate<T> isUnknown;
    protected final boolean unmodifiable;
    protected final List<T> preAddedAssets;
    protected final Class<? extends JsonAsset<?>> idProvider;
    protected final Map<Class<? extends JsonAssetWithMap<?, ?>>, Map<K, Set<Object>>> childAssetsMap = new ConcurrentHashMap();
    @Nonnull
    protected Set<Class<? extends JsonAssetWithMap>> loadedContainedAssetsFor = new HashSet<Class<? extends JsonAssetWithMap>>();
    public static boolean DISABLE_DYNAMIC_DEPENDENCIES = false;

    public AssetStore(@Nonnull Builder<K, T, M, ?> builder) {
        this.kClass = builder.kClass;
        this.tClass = builder.tClass;
        this.logger = HytaleLogger.get("AssetStore|" + this.tClass.getSimpleName());
        this.path = builder.path;
        this.extension = builder.extension;
        this.codec = builder.codec;
        this.keyFunction = builder.keyFunction;
        this.isUnknown = builder.isUnknown == null ? v -> false : builder.isUnknown;
        this.loadsAfter = builder.loadsAfter;
        this.unmodifiableLoadsAfter = Collections.unmodifiableSet(builder.loadsAfter);
        this.loadsBefore = Collections.unmodifiableSet(builder.loadsBefore);
        this.assetMap = builder.assetMap;
        this.replaceOnRemove = builder.replaceOnRemove;
        this.unmodifiable = builder.unmodifiable;
        this.preAddedAssets = builder.preAddedAssets;
        this.idProvider = builder.idProvider;
        if (builder.replaceOnRemove == null && ((AssetMap)this.assetMap).requireReplaceOnRemove()) {
            throw new IllegalArgumentException("AssetStore for " + this.tClass.getSimpleName() + " using an AssetMap of " + this.assetMap.getClass().getSimpleName() + " must use #setReplaceOnRemove");
        }
    }

    protected abstract IEventBus getEventBus();

    public abstract void addFileMonitor(@Nonnull String var1, Path var2);

    public abstract void removeFileMonitor(Path var1);

    protected abstract void handleRemoveOrUpdate(Set<K> var1, Map<K, T> var2, @Nonnull AssetUpdateQuery var3);

    @Nonnull
    public Class<K> getKeyClass() {
        return this.kClass;
    }

    @Nonnull
    public Class<T> getAssetClass() {
        return this.tClass;
    }

    public String getPath() {
        return this.path;
    }

    @Nonnull
    public String getExtension() {
        return this.extension;
    }

    public AssetCodec<K, T> getCodec() {
        return this.codec;
    }

    public Function<T, K> getKeyFunction() {
        return this.keyFunction;
    }

    @Nonnull
    public Set<Class<? extends JsonAsset<?>>> getLoadsAfter() {
        return this.unmodifiableLoadsAfter;
    }

    public M getAssetMap() {
        return this.assetMap;
    }

    public Function<K, T> getReplaceOnRemove() {
        return this.replaceOnRemove;
    }

    public boolean isUnmodifiable() {
        return this.unmodifiable;
    }

    public List<T> getPreAddedAssets() {
        return this.preAddedAssets;
    }

    public <X extends JsonAssetWithMap> boolean hasLoadedContainedAssetsFor(Class<X> x) {
        return this.loadedContainedAssetsFor.contains(x);
    }

    public Class<? extends JsonAsset<?>> getIdProvider() {
        return this.idProvider;
    }

    @Nonnull
    public HytaleLogger getLogger() {
        return this.logger;
    }

    public void simplifyLoadBeforeDependencies() {
        for (Class<? extends JsonAsset<?>> clazz : this.loadsBefore) {
            AssetRegistry.getAssetStore(clazz).loadsAfter.add(this.tClass);
        }
    }

    @Deprecated
    public <D extends JsonAsset<?>> void injectLoadsAfter(Class<D> aClass) {
        if (DISABLE_DYNAMIC_DEPENDENCIES) {
            throw new IllegalArgumentException("Asset stores have already loaded! Injecting a dependency is now pointless.");
        }
        this.loadsAfter.add(aClass);
    }

    @Nullable
    public K decodeFilePathKey(@Nonnull Path path) {
        String fileName = path.getFileName().toString();
        return this.decodeStringKey(fileName.substring(0, fileName.length() - this.extension.length()));
    }

    @Nullable
    public K decodeStringKey(String key) {
        if (this.codec.getKeyCodec().getChildCodec() == Codec.STRING) {
            return (K)key;
        }
        return this.codec.getKeyCodec().getChildCodec().decode(new BsonString(key));
    }

    @Nullable
    public K transformKey(@Nullable Object o) {
        if (o == null) {
            return null;
        }
        if (o.getClass().equals(this.kClass)) {
            return (K)o;
        }
        return this.decodeStringKey(o.toString());
    }

    public void validate(@Nullable K key, @Nonnull ValidationResults results, ExtraInfo extraInfo) {
        if (key == null) {
            return;
        }
        if (((AssetMap)this.assetMap).getAsset(key) != null) {
            return;
        }
        if (extraInfo instanceof AssetExtraInfo) {
            for (AssetExtraInfo.Data data = ((AssetExtraInfo)extraInfo).getData(); data != null; data = data.getContainerData()) {
                if (!data.containsAsset(this.tClass, key)) continue;
                return;
            }
        }
        results.fail("Asset '" + String.valueOf(key) + "' of type " + this.tClass.getName() + " doesn't exist!");
    }

    public void validateCodecDefaults() {
        ExtraInfo extraInfo = new ExtraInfo(Integer.MAX_VALUE, AssetValidationResults::new);
        this.codec.validateDefaults(extraInfo, new HashSet());
        extraInfo.getValidationResults().logOrThrowValidatorExceptions(this.logger, "Default Asset Validation Failed!\n");
    }

    public void logDependencies() {
        ExtraInfo extraInfo = new ExtraInfo(Integer.MAX_VALUE, AssetValidationResults::new);
        HashSet tested = new HashSet();
        this.codec.validateDefaults(extraInfo, tested);
        HashSet assetClasses = new HashSet();
        HashSet maybeLateAssetClasses = new HashSet();
        for (Codec<?> other : tested) {
            if (other instanceof BuilderCodec) {
                for (BuilderCodec builderCodec = (BuilderCodec)other; builderCodec != null; builderCodec = builderCodec.getParent()) {
                    for (List value : builderCodec.getEntries().values()) {
                        for (BuilderField field : value) {
                            List<Validator<?>> validators;
                            if (!field.supportsVersion(extraInfo.getVersion()) || (validators = field.getValidators()) == null) continue;
                            for (Validator<Object> validator : validators) {
                                Validator<?> validator2 = validator;
                                if (validator2 instanceof ArrayValidator) {
                                    ArrayValidator arrayValidator = (ArrayValidator)validator2;
                                    validator = arrayValidator.getValidator();
                                } else {
                                    validator2 = validator;
                                    if (validator2 instanceof MapKeyValidator) {
                                        MapKeyValidator arrayValidator = (MapKeyValidator)validator2;
                                        validator = arrayValidator.getKeyValidator();
                                    } else {
                                        validator2 = validator;
                                        if (validator2 instanceof MapValueValidator) {
                                            MapValueValidator arrayValidator = (MapValueValidator)validator2;
                                            validator = arrayValidator.getValueValidator();
                                        }
                                    }
                                }
                                if (!(validator instanceof AssetKeyValidator)) continue;
                                AssetKeyValidator assetKeyValidator = (AssetKeyValidator)validator;
                                assetClasses.add(assetKeyValidator.getStore().getAssetClass());
                            }
                        }
                    }
                }
                continue;
            }
            if (!(other instanceof ContainedAssetCodec)) continue;
            ContainedAssetCodec containedAssetCodec = (ContainedAssetCodec)other;
            maybeLateAssetClasses.add(containedAssetCodec.getAssetClass());
        }
        HashSet<Class> missing = new HashSet<Class>();
        HashSet<Class> unused = new HashSet<Class>();
        for (Class clazz : assetClasses) {
            if (this.loadsAfter.contains(clazz)) continue;
            missing.add(clazz);
        }
        for (Class clazz : this.loadsAfter) {
            if (assetClasses.contains(clazz) || maybeLateAssetClasses.contains(clazz)) continue;
            unused.add(clazz);
        }
        if (!missing.isEmpty()) {
            this.logger.at(Level.WARNING).log("\nMissing Dependencies:" + missing.stream().map(Object::toString).collect(Collectors.joining("\n- ", "\n- ", "")));
        }
        if (!unused.isEmpty()) {
            this.logger.at(Level.WARNING).log("\nUnused Dependencies:" + unused.stream().map(Object::toString).collect(Collectors.joining("\n- ", "\n- ", "")));
        }
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssetsFromDirectory(@Nonnull String packKey, @Nonnull Path assetsPath) throws IOException {
        if (this.unmodifiable) {
            throw new UnsupportedOperationException("AssetStore is unmodifiable!");
        }
        Objects.requireNonNull(assetsPath, "assetsPath can't be null");
        final ArrayList<Path> files = new ArrayList<Path>();
        Set<FileVisitOption> optionsSet = Set.of();
        Files.walkFileTree(assetsPath, optionsSet, Integer.MAX_VALUE, (FileVisitor<? super Path>)new SimpleFileVisitor<Path>(this){
            final /* synthetic */ AssetStore this$0;
            {
                this.this$0 = this$0;
            }

            @Override
            @Nonnull
            public FileVisitResult visitFile(@Nonnull Path file, @Nonnull BasicFileAttributes attrs) throws IOException {
                if (attrs.isRegularFile() && file.toString().endsWith(this.this$0.extension)) {
                    files.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return this.loadAssetsFromPaths(packKey, files);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssetsFromPaths(@Nonnull String packKey, @Nonnull List<Path> paths) {
        return this.loadAssetsFromPaths(packKey, paths, AssetUpdateQuery.DEFAULT);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssetsFromPaths(@Nonnull String packKey, @Nonnull Collection<Path> paths, @Nonnull AssetUpdateQuery query) {
        return this.loadAssetsFromPaths(packKey, paths, query, false);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssetsFromPaths(@Nonnull String packKey, @Nonnull Collection<Path> paths, @Nonnull AssetUpdateQuery query, boolean forceLoadAll) {
        if (this.unmodifiable) {
            throw new UnsupportedOperationException("AssetStore is unmodifiable!");
        }
        Objects.requireNonNull(paths, "paths can't be null");
        long start = System.nanoTime();
        HashSet<Path> documents = new HashSet<Path>();
        for (Path path : paths) {
            Path normalize = path.toAbsolutePath().normalize();
            Set keys = ((AssetMap)this.assetMap).getKeys(normalize);
            if (keys != null) {
                for (Object key : keys) {
                    this.loadAllChildren(documents, key);
                }
            }
            documents.add(normalize);
            this.loadAllChildren(documents, this.decodeFilePathKey(path));
        }
        ArrayList<RawAsset<K>> rawAssets = new ArrayList<RawAsset<K>>(documents.size());
        for (Path p : documents) {
            rawAssets.add(new RawAsset<K>(this.decodeFilePathKey(p), p));
        }
        Map map = Collections.synchronizedMap(new Object2ObjectLinkedOpenHashMap());
        ConcurrentHashMap loadedKeyToPathMap = new ConcurrentHashMap();
        ConcurrentHashMap.KeySetView failedToLoadKeys = ConcurrentHashMap.newKeySet();
        ConcurrentHashMap.KeySetView failedToLoadPaths = ConcurrentHashMap.newKeySet();
        ConcurrentHashMap<Class<? extends JsonAssetWithMap>, AssetLoadResult> childAssetResults = new ConcurrentHashMap<Class<? extends JsonAssetWithMap>, AssetLoadResult>();
        this.loadAssets0(packKey, map, rawAssets, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, query, forceLoadAll, childAssetResults);
        long end = System.nanoTime();
        long diff = end - start;
        this.logger.at(Level.FINE).log("Loaded %d and removed %s (%s total) of %s from %s files in %s", map.size(), failedToLoadKeys.size(), ((AssetMap)this.assetMap).getAssetCount(), this.tClass.getSimpleName(), paths.size(), FormatUtil.nanosToString(diff));
        return new AssetLoadResult(map, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, childAssetResults);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadBuffersWithKeys(@Nonnull String packKey, @Nonnull List<RawAsset<K>> preLoaded, @Nonnull AssetUpdateQuery query, boolean forceLoadAll) {
        long start = System.nanoTime();
        HashSet<Path> documents = new HashSet<Path>();
        for (RawAsset<K> rawAsset : preLoaded) {
            this.loadAllChildren(documents, rawAsset.getKey());
        }
        ArrayList<RawAsset<K>> rawAssets = new ArrayList<RawAsset<K>>(preLoaded.size() + documents.size());
        rawAssets.addAll(preLoaded);
        for (Path p : documents) {
            rawAssets.add(new RawAsset<K>(this.decodeFilePathKey(p), p));
        }
        Map map = Collections.synchronizedMap(new Object2ObjectLinkedOpenHashMap());
        ConcurrentHashMap loadedKeyToPathMap = new ConcurrentHashMap();
        ConcurrentHashMap.KeySetView failedToLoadKeys = ConcurrentHashMap.newKeySet();
        ConcurrentHashMap.KeySetView failedToLoadPaths = ConcurrentHashMap.newKeySet();
        ConcurrentHashMap<Class<? extends JsonAssetWithMap>, AssetLoadResult> childAssetResults = new ConcurrentHashMap<Class<? extends JsonAssetWithMap>, AssetLoadResult>();
        this.loadAssets0(packKey, map, rawAssets, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, query, forceLoadAll, childAssetResults);
        long end = System.nanoTime();
        long diff = end - start;
        this.logger.at(Level.FINE).log("Loaded %d and removed %s (%s total) of %s via loadBuffersWithKeys in %s", map.size(), failedToLoadKeys.size(), ((AssetMap)this.assetMap).getAssetCount(), this.tClass.getSimpleName(), FormatUtil.nanosToString(diff));
        return new AssetLoadResult(map, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, childAssetResults);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssets(@Nonnull String packKey, @Nonnull List<T> assets) {
        return this.loadAssets(packKey, assets, AssetUpdateQuery.DEFAULT);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssets(@Nonnull String packKey, @Nonnull List<T> assets, @Nonnull AssetUpdateQuery query) {
        return this.loadAssets(packKey, assets, query, false);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssets(@Nonnull String packKey, @Nonnull List<T> assets, @Nonnull AssetUpdateQuery query, boolean forceLoadAll) {
        if (this.unmodifiable) {
            throw new UnsupportedOperationException("AssetStore is unmodifiable!");
        }
        Objects.requireNonNull(assets, "assets can't be null");
        long start = System.nanoTime();
        Map loadedAssets = Collections.synchronizedMap(new Object2ObjectLinkedOpenHashMap());
        HashSet<Path> documents = new HashSet<Path>();
        this.loadAllChildren(loadedAssets, assets, documents);
        ArrayList<RawAsset<K>> rawAssets = new ArrayList<RawAsset<K>>(documents.size());
        for (Path p : documents) {
            rawAssets.add(new RawAsset<K>(this.decodeFilePathKey(p), p));
        }
        ConcurrentHashMap loadedKeyToPathMap = new ConcurrentHashMap();
        ConcurrentHashMap.KeySetView failedToLoadKeys = ConcurrentHashMap.newKeySet();
        ConcurrentHashMap.KeySetView failedToLoadPaths = ConcurrentHashMap.newKeySet();
        ConcurrentHashMap<Class<? extends JsonAssetWithMap>, AssetLoadResult> childAssetResults = new ConcurrentHashMap<Class<? extends JsonAssetWithMap>, AssetLoadResult>();
        this.loadAssets0(packKey, loadedAssets, rawAssets, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, query, forceLoadAll, childAssetResults);
        long end = System.nanoTime();
        long diff = end - start;
        this.logger.at(Level.FINE).log("Loaded %d and removed %s (%s total) of %s via loadAssets in %s", loadedAssets.size(), failedToLoadKeys.size(), ((AssetMap)this.assetMap).getAssetCount(), this.tClass.getSimpleName(), FormatUtil.nanosToString(diff));
        return new AssetLoadResult(loadedAssets, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, childAssetResults);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssetsWithReferences(@Nonnull String packKey, @Nonnull Map<T, List<AssetReferences<?, ?>>> assets) {
        return this.loadAssetsWithReferences(packKey, assets, AssetUpdateQuery.DEFAULT);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssetsWithReferences(@Nonnull String packKey, @Nonnull Map<T, List<AssetReferences<?, ?>>> assets, @Nonnull AssetUpdateQuery query) {
        return this.loadAssetsWithReferences(packKey, assets, query, false);
    }

    @Nonnull
    public AssetLoadResult<K, T> loadAssetsWithReferences(@Nonnull String packKey, @Nonnull Map<T, List<AssetReferences<?, ?>>> assets, @Nonnull AssetUpdateQuery query, boolean forceLoadAll) {
        if (this.unmodifiable) {
            throw new UnsupportedOperationException("AssetStore is unmodifiable!");
        }
        Objects.requireNonNull(assets, "assets can't be null");
        long start = System.nanoTime();
        Map loadedAssets = Collections.synchronizedMap(new Object2ObjectLinkedOpenHashMap());
        Set<T> assetKeys = assets.keySet();
        HashSet<Path> documents = new HashSet<Path>();
        this.loadAllChildren(loadedAssets, assetKeys, documents);
        ArrayList<RawAsset<K>> rawAssets = new ArrayList<RawAsset<K>>(documents.size());
        for (Path p : documents) {
            rawAssets.add(new RawAsset<K>(this.decodeFilePathKey(p), p));
        }
        ConcurrentHashMap loadedKeyToPathMap = new ConcurrentHashMap();
        ConcurrentHashMap.KeySetView failedToLoadKeys = ConcurrentHashMap.newKeySet();
        ConcurrentHashMap.KeySetView failedToLoadPaths = ConcurrentHashMap.newKeySet();
        ConcurrentHashMap<Class<? extends JsonAssetWithMap>, AssetLoadResult> childAssetResults = new ConcurrentHashMap<Class<? extends JsonAssetWithMap>, AssetLoadResult>();
        this.loadAssets0(packKey, loadedAssets, rawAssets, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, query, forceLoadAll, childAssetResults);
        for (Map.Entry<T, List<AssetReferences<?, ?>>> entry : assets.entrySet()) {
            JsonAssetWithMap asset = (JsonAssetWithMap)entry.getKey();
            Objects.requireNonNull(asset, "asset can't be null");
            K key = this.keyFunction.apply(asset);
            if (key == null) {
                throw new NullPointerException(String.format("key can't be null: %s", asset));
            }
            for (AssetReferences<?, ?> references : entry.getValue()) {
                references.addChildAssetReferences(this.tClass, key);
            }
        }
        long end = System.nanoTime();
        long diff = end - start;
        this.logger.at(Level.FINE).log("Loaded %d and removed %s (%s total) of %s via loadAssetsWithReferences in %s", loadedAssets.size(), failedToLoadKeys.size(), ((AssetMap)this.assetMap).getAssetCount(), this.tClass.getSimpleName(), FormatUtil.nanosToString(diff));
        return new AssetLoadResult(loadedAssets, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, childAssetResults);
    }

    @Nonnull
    public Set<K> removeAssetWithPaths(@Nonnull String packKey, @Nonnull List<Path> paths) {
        return this.removeAssetWithPaths(packKey, paths, AssetUpdateQuery.DEFAULT);
    }

    @Nonnull
    public Set<K> removeAssetWithPaths(@Nonnull String packKey, @Nonnull List<Path> paths, @Nonnull AssetUpdateQuery assetUpdateQuery) {
        if (this.unmodifiable) {
            throw new UnsupportedOperationException("AssetStore is unmodifiable!");
        }
        HashSet allKeys = new HashSet();
        for (Path path : paths) {
            Path normalize = path.toAbsolutePath().normalize();
            Set keys = ((AssetMap)this.assetMap).getKeys(normalize);
            if (keys == null) continue;
            allKeys.addAll(keys);
        }
        return this.removeAssets(packKey, false, allKeys, assetUpdateQuery);
    }

    @Nonnull
    public Set<K> removeAssetWithPath(Path path) {
        return this.removeAssetWithPath(path, AssetUpdateQuery.DEFAULT);
    }

    @Nonnull
    public Set<K> removeAssetWithPath(Path path, @Nonnull AssetUpdateQuery assetUpdateQuery) {
        if (this.unmodifiable) {
            throw new UnsupportedOperationException("AssetStore is unmodifiable!");
        }
        Path normalize = path.toAbsolutePath().normalize();
        Set keys = ((AssetMap)this.assetMap).getKeys(normalize);
        if (keys != null) {
            return this.removeAssets("Hytale:Hytale", true, keys, assetUpdateQuery);
        }
        return Collections.emptySet();
    }

    @Nonnull
    public Set<K> removeAssets(@Nonnull Collection<K> keys) {
        return this.removeAssets("Hytale:Hytale", true, keys, AssetUpdateQuery.DEFAULT);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Nonnull
    public Set<K> removeAssets(@Nonnull String packKey, boolean all, @Nonnull Collection<K> keys, @Nonnull AssetUpdateQuery assetUpdateQuery) {
        if (this.unmodifiable) {
            throw new UnsupportedOperationException("AssetStore is unmodifiable!");
        }
        long start = System.nanoTime();
        AssetRegistry.ASSET_LOCK.writeLock().lock();
        try {
            IEventDispatcher<RemovedAssetsEvent, RemovedAssetsEvent> dispatcher;
            HashSet<Object> toBeRemoved = new HashSet<Object>();
            HashSet temp = new HashSet();
            for (K key2 : keys) {
                toBeRemoved.add(key2);
                Path path = ((AssetMap)this.assetMap).getPath(key2);
                if (path != null) {
                    this.logRemoveAsset(key2, path);
                } else {
                    this.logRemoveAsset(key2, null);
                }
                temp.clear();
                this.collectAllChildren(key2, temp);
                this.logRemoveChildren(key2, temp);
                toBeRemoved.addAll(temp);
            }
            if (toBeRemoved.isEmpty()) {
                HashSet<Object> hashSet = toBeRemoved;
                return hashSet;
            }
            this.removeChildrenAssets(packKey, toBeRemoved);
            ArrayList<Map.Entry<String, Object>> pathsToReload = null;
            if (all) {
                ((AssetMap)this.assetMap).remove(toBeRemoved);
            } else {
                pathsToReload = new ArrayList<Map.Entry<String, Object>>();
                ((AssetMap)this.assetMap).remove(packKey, toBeRemoved, pathsToReload);
            }
            if (this.replaceOnRemove != null) {
                Map replacements = toBeRemoved.stream().collect(Collectors.toMap(Function.identity(), key -> {
                    JsonAssetWithMap replacement = (JsonAssetWithMap)this.replaceOnRemove.apply(key);
                    Objects.requireNonNull(replacement, "Replacement can't be null!");
                    K replacementKey = this.keyFunction.apply(replacement);
                    if (replacementKey == null) {
                        throw new NullPointerException(key.toString());
                    }
                    if (!key.equals(replacementKey)) {
                        this.logger.at(Level.WARNING).log("Replacement key '%s' doesn't match key '%s'", replacementKey, key);
                    }
                    return replacement;
                }));
                ((AssetMap)this.assetMap).putAll("Hytale:Hytale", this.codec, replacements, Collections.emptyMap(), Collections.emptyMap());
                this.handleRemoveOrUpdate(null, replacements, AssetUpdateQuery.DEFAULT);
                this.loadContainedAssets("Hytale:Hytale", replacements.values(), new HashMap<Class<? extends JsonAssetWithMap>, AssetLoadResult>(), AssetUpdateQuery.DEFAULT, false);
            } else {
                this.handleRemoveOrUpdate(toBeRemoved, null, assetUpdateQuery);
            }
            if (pathsToReload != null) {
                for (Map.Entry entry : pathsToReload) {
                    if (entry.getValue() instanceof Path) {
                        this.loadAssetsFromPaths((String)entry.getKey(), List.of((Path)entry.getValue()));
                        continue;
                    }
                    this.loadAssets((String)entry.getKey(), List.of((JsonAssetWithMap)entry.getValue()));
                }
            }
            long end = System.nanoTime();
            long diff = end - start;
            this.logger.at(Level.INFO).log("Removed %d (%s total) of %s via removeAssets in %s", toBeRemoved.size(), ((AssetMap)this.assetMap).getAssetCount(), this.tClass.getSimpleName(), FormatUtil.nanosToString(diff));
            if (!toBeRemoved.isEmpty() && (dispatcher = this.getEventBus().dispatchFor(RemovedAssetsEvent.class, this.tClass)).hasListener()) {
                dispatcher.dispatch(new RemovedAssetsEvent(this.tClass, this.assetMap, toBeRemoved, this.replaceOnRemove != null));
            }
            HashSet<Object> hashSet = toBeRemoved;
            return hashSet;
        }
        finally {
            AssetRegistry.ASSET_LOCK.writeLock().unlock();
        }
    }

    public void removeAssetPack(@Nonnull String name) {
        AssetRegistry.ASSET_LOCK.writeLock().lock();
        try {
            Set assets = ((AssetMap)this.assetMap).getKeysForPack(name);
            if (assets == null) {
                return;
            }
            this.removeAssets(name, false, assets, AssetUpdateQuery.DEFAULT);
        }
        finally {
            AssetRegistry.ASSET_LOCK.writeLock().unlock();
        }
    }

    public AssetLoadResult<K, T> writeAssetToDisk(@Nonnull AssetPack pack, @Nonnull Map<Path, T> assetsByPath) throws IOException {
        return this.writeAssetToDisk(pack, assetsByPath, AssetUpdateQuery.DEFAULT);
    }

    public AssetLoadResult<K, T> writeAssetToDisk(@Nonnull AssetPack pack, @Nonnull Map<Path, T> assetsByPath, @Nonnull AssetUpdateQuery query) throws IOException {
        if (pack.isImmutable()) {
            throw new IOException("Pack is immutable");
        }
        for (Map.Entry<Path, T> entry : assetsByPath.entrySet()) {
            JsonAssetWithMap asset = (JsonAssetWithMap)entry.getValue();
            Object id = asset.getId();
            Path assetPath = pack.getRoot().resolve("Server").resolve(this.path).resolve(entry.getKey());
            AssetExtraInfo.Data data = this.codec.getData(asset);
            Object parentId = data == null ? null : data.getParentKey();
            BsonValue bsonValue = this.codec.encode(asset, new AssetExtraInfo(assetPath, new AssetExtraInfo.Data(this.tClass, id, this.transformKey(parentId))));
            Files.writeString(assetPath, (CharSequence)bsonValue.toString(), StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        }
        return this.loadAssets(pack.getName(), new ArrayList<T>(assetsByPath.values()), query);
    }

    @Nonnull
    public T decode(@Nonnull String packKey, @Nonnull K key, @Nonnull BsonDocument document) {
        KeyedCodec<K> parentCodec = this.codec.getParentCodec();
        Object parentKey = parentCodec != null ? (Object)parentCodec.getOrNull(document) : null;
        RawJsonReader reader = RawJsonReader.fromBuffer(document.toString().toCharArray());
        try {
            JsonAssetWithMap parent;
            AssetExtraInfo extraInfo = new AssetExtraInfo(new AssetExtraInfo.Data(this.getAssetClass(), key, parentKey));
            if (parentKey == null) {
                reader.consumeWhiteSpace();
                JsonAssetWithMap asset = (JsonAssetWithMap)this.codec.decodeJsonAsset(reader, extraInfo);
                if (asset == null) {
                    throw new NullPointerException(document.toString());
                }
                extraInfo.getValidationResults().logOrThrowValidatorExceptions(this.logger);
                this.logUnusedKeys(key, null, extraInfo);
                return (T)asset;
            }
            JsonAssetWithMap jsonAssetWithMap = parent = parentKey.equals("super") ? (JsonAssetWithMap)((AssetMap)this.assetMap).getAsset(packKey, key) : (JsonAssetWithMap)((AssetMap)this.assetMap).getAsset((Object)parentKey);
            if (parent == null) {
                throw new NullPointerException(parentKey.toString());
            }
            reader.consumeWhiteSpace();
            JsonAssetWithMap asset = this.codec.decodeAndInheritJsonAsset(reader, parent, extraInfo);
            if (asset == null) {
                throw new NullPointerException(document.toString());
            }
            extraInfo.getValidationResults().logOrThrowValidatorExceptions(this.logger);
            this.logUnusedKeys(key, null, extraInfo);
            return (T)asset;
        }
        catch (IOException e) {
            throw SneakyThrow.sneakyThrow(e);
        }
    }

    public <CK> void addChildAssetReferences(K parentKey, Class<? extends JsonAssetWithMap<CK, ?>> childAssetClass, @Nonnull Set<CK> childKeys) {
        this.childAssetsMap.computeIfAbsent(childAssetClass, k -> new ConcurrentHashMap()).computeIfAbsent(parentKey, k -> ConcurrentHashMap.newKeySet()).addAll(childKeys);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    protected void loadAssets0(@Nonnull String packKey, @Nonnull Map<K, T> loadedAssets, @Nonnull List<RawAsset<K>> preLoaded, @Nonnull Map<K, Path> loadedKeyToPathMap, @Nonnull Set<K> failedToLoadKeys, @Nonnull Set<Path> failedToLoadPaths, @Nonnull AssetUpdateQuery query, boolean forceLoadAll, @Nonnull Map<Class<? extends JsonAssetWithMap>, AssetLoadResult> childAssetResults) {
        ConcurrentHashMap loadedAssetChildren = new ConcurrentHashMap();
        this.decodeAssets(packKey, preLoaded, loadedAssets, loadedKeyToPathMap, loadedAssetChildren, failedToLoadKeys, failedToLoadPaths, this.assetMap, query, forceLoadAll);
        AssetRegistry.ASSET_LOCK.writeLock().lock();
        try {
            IEventDispatcher<AssetsEvent, AssetsEvent> dispatcher;
            IEventDispatcher<GenerateAssetsEvent, GenerateAssetsEvent> generateDispatcher = this.getEventBus().dispatchFor(GenerateAssetsEvent.class, this.tClass);
            if (generateDispatcher.hasListener()) {
                generateDispatcher.dispatch(new GenerateAssetsEvent<K, T, M>(this.tClass, this.assetMap, loadedAssets, loadedAssetChildren));
            }
            HashMap toBeRemovedMap = new HashMap();
            HashSet temp = new HashSet();
            for (K key2 : failedToLoadKeys) {
                if (toBeRemovedMap.putIfAbsent(key2, key2) != null) continue;
                this.logRemoveAsset(key2, null);
                temp.clear();
                this.collectAllChildren(key2, temp);
                for (Object k2 : temp) {
                    toBeRemovedMap.putIfAbsent(k2, key2);
                }
            }
            for (Path path : failedToLoadPaths) {
                Set keys = ((AssetMap)this.assetMap).getKeys(path);
                if (keys == null) continue;
                for (Object key3 : keys) {
                    if (toBeRemovedMap.putIfAbsent(key3, key3) != null) continue;
                    this.logRemoveAsset(key3, path);
                    temp.clear();
                    this.collectAllChildren(key3, temp);
                    for (Object k3 : temp) {
                        toBeRemovedMap.putIfAbsent(k3, key3);
                    }
                }
            }
            ((AssetMap)this.assetMap).putAll(packKey, this.codec, loadedAssets, loadedKeyToPathMap, loadedAssetChildren);
            Set toBeRemoved = toBeRemovedMap.keySet();
            if (!toBeRemoved.isEmpty()) {
                this.logRemoveChildren(toBeRemovedMap);
                this.removeChildrenAssets(packKey, toBeRemoved);
            }
            if (this.replaceOnRemove != null && !toBeRemoved.isEmpty()) {
                Map replacements = toBeRemoved.stream().filter(k -> ((AssetMap)this.assetMap).getAsset((Object)k) != null).collect(Collectors.toMap(Function.identity(), key -> {
                    JsonAssetWithMap replacement = (JsonAssetWithMap)this.replaceOnRemove.apply(key);
                    Objects.requireNonNull(replacement, "Replacement can't be null!");
                    K replacementKey = this.keyFunction.apply(replacement);
                    if (replacementKey == null) {
                        throw new NullPointerException(key.toString());
                    }
                    if (!key.equals(replacementKey)) {
                        this.logger.at(Level.WARNING).log("Replacement key '%s' doesn't match key '%s'", replacementKey, key);
                    }
                    return replacement;
                }));
                ((AssetMap)this.assetMap).putAll("Hytale:Hytale", this.codec, replacements, Collections.emptyMap(), Collections.emptyMap());
                replacements.putAll(loadedAssets);
                this.handleRemoveOrUpdate(null, replacements, query);
            } else {
                ((AssetMap)this.assetMap).remove(toBeRemoved);
                this.handleRemoveOrUpdate(toBeRemoved, loadedAssets, query);
            }
            this.loadContainedAssets(packKey, loadedAssets.values(), childAssetResults, query, forceLoadAll);
            this.reloadChildrenContainerAssets(packKey, loadedAssets);
            if (!loadedAssets.isEmpty() && (dispatcher = this.getEventBus().dispatchFor(LoadedAssetsEvent.class, this.tClass)).hasListener()) {
                dispatcher.dispatch(new LoadedAssetsEvent<K, T, M>(this.tClass, this.assetMap, loadedAssets, false, query));
            }
            if (!toBeRemoved.isEmpty() && (dispatcher = this.getEventBus().dispatchFor(RemovedAssetsEvent.class, this.tClass)).hasListener()) {
                dispatcher.dispatch(new RemovedAssetsEvent(this.tClass, this.assetMap, toBeRemoved, this.replaceOnRemove != null));
            }
        }
        finally {
            AssetRegistry.ASSET_LOCK.writeLock().unlock();
        }
    }

    private void reloadChildrenContainerAssets(@Nonnull String packKey, @Nonnull Map<K, T> loadedAssets) {
        HashSet<Path> toReload = new HashSet<Path>();
        HashMap toReloadTypes = new HashMap();
        for (Map.Entry<K, T> entry : loadedAssets.entrySet()) {
            K key = entry.getKey();
            Path path = ((AssetMap)this.assetMap).getPath(key);
            if (path == null) continue;
            this.collectChildrenInDifferentFile(key, path, toReload, toReloadTypes, loadedAssets.keySet());
        }
        AssetUpdateQuery query = null;
        if (!toReload.isEmpty()) {
            query = new AssetUpdateQuery(true, AssetUpdateQuery.RebuildCache.DEFAULT);
            this.loadAssetsFromPaths(packKey, toReload, query, true);
        }
        if (!toReloadTypes.isEmpty()) {
            if (query == null) {
                query = new AssetUpdateQuery(true, AssetUpdateQuery.RebuildCache.DEFAULT);
            }
            for (Map.Entry entry : toReloadTypes.entrySet()) {
                AssetStore assetStore = AssetRegistry.getAssetStore((Class)entry.getKey());
                assetStore.loadAssetsFromPaths(packKey, (Collection)entry.getValue(), query, true);
            }
        }
    }

    private void collectChildrenInDifferentFile(K key, @Nonnull Path path, @Nonnull Set<Path> paths, @Nonnull Map<Class<? extends JsonAssetWithMap<?, ?>>, Set<Path>> typedPaths, @Nonnull Set<K> ignore) {
        Set<K> children = ((AssetMap)this.assetMap).getChildren(key);
        for (K child : children) {
            AssetExtraInfo.Data root;
            if (ignore.contains(child)) continue;
            Path childPath = ((AssetMap)this.assetMap).getPath(child);
            if (childPath != null && !path.equals(childPath)) {
                paths.add(childPath);
                continue;
            }
            AssetExtraInfo.Data data = this.codec.getData((JsonAssetWithMap)((AssetMap)this.assetMap).getAsset(child));
            AssetExtraInfo.Data data2 = root = data != null ? data.getRootContainerData() : null;
            if (root != null) {
                if (root.getAssetClass() == this.tClass) {
                    Object rootKey = root.getKey();
                    if (ignore.contains(rootKey)) continue;
                    Path rootPath = ((AssetMap)this.assetMap).getPath((Object)rootKey);
                    if (!path.equals(rootPath)) {
                        paths.add(rootPath);
                        continue;
                    }
                } else {
                    Class<? extends JsonAsset<?>> assetClass = root.getAssetClass();
                    if (assetClass == null) continue;
                    AssetStore assetStore = AssetRegistry.getAssetStore(assetClass);
                    Path rootPath = ((AssetMap)assetStore.getAssetMap()).getPath((Object)root.getKey());
                    if (rootPath != null) {
                        typedPaths.computeIfAbsent(assetClass, k -> new HashSet()).add(rootPath);
                        continue;
                    }
                }
            }
            this.collectChildrenInDifferentFile(child, path, paths, typedPaths, ignore);
        }
    }

    protected void removeChildrenAssets(@Nonnull String packKey, @Nonnull Set<K> toBeRemoved) {
        for (Map.Entry<Class<JsonAssetWithMap<?, ?>>, Map<K, Set<Object>>> entry : this.childAssetsMap.entrySet()) {
            Class<? extends JsonAssetWithMap<?, ?>> k = entry.getKey();
            Map<K, Set<Object>> value = entry.getValue();
            HashSet<Object> allChildKeys = null;
            for (K key : toBeRemoved) {
                Set<Object> childKeys = value.remove(key);
                if (childKeys == null) continue;
                if (allChildKeys == null) {
                    allChildKeys = new HashSet<Object>();
                }
                allChildKeys.addAll(childKeys);
            }
            if (allChildKeys == null || allChildKeys.isEmpty()) continue;
            AssetRegistry.getAssetStore(k).removeAssets(packKey, false, allChildKeys, AssetUpdateQuery.DEFAULT);
        }
    }

    protected void loadContainedAssets(@Nonnull String packKey, @Nonnull Collection<T> assets, @Nonnull Map<Class<? extends JsonAssetWithMap>, AssetLoadResult> childAssetsResults, @Nonnull AssetUpdateQuery query, boolean forceLoadAll) {
        HashMap containedAssetsByClass = new HashMap();
        for (JsonAssetWithMap jsonAssetWithMap : assets) {
            AssetExtraInfo.Data data = this.codec.getData(jsonAssetWithMap);
            if (data == null) continue;
            data.fetchContainedAssets(this.keyFunction.apply(jsonAssetWithMap), containedAssetsByClass);
        }
        for (Map.Entry entry : containedAssetsByClass.entrySet()) {
            Class clazz = (Class)entry.getKey();
            Map containedAssets = (Map)entry.getValue();
            AssetStore assetStore = AssetRegistry.getAssetStore(clazz);
            this.loadedContainedAssetsFor.add(clazz);
            ArrayList childList = new ArrayList();
            for (Map.Entry entry2 : containedAssets.entrySet()) {
                Object k2 = entry2.getKey();
                for (Object contained : (List)entry2.getValue()) {
                    Object containedKey = assetStore.getKeyFunction().apply(contained);
                    this.childAssetsMap.computeIfAbsent(assetStore.getAssetClass(), k -> new ConcurrentHashMap()).computeIfAbsent(k2, k -> ConcurrentHashMap.newKeySet()).add(containedKey);
                    childList.add(contained);
                }
            }
            AssetLoadResult result = assetStore.loadAssets(packKey, childList, query, forceLoadAll);
            childAssetsResults.put(clazz, result);
        }
        HashMap containedRawAssetsByClass = new HashMap();
        for (JsonAssetWithMap jsonAssetWithMap : assets) {
            AssetExtraInfo.Data data = this.codec.getData(jsonAssetWithMap);
            if (data == null) continue;
            data.fetchContainedRawAssets(this.keyFunction.apply(jsonAssetWithMap), containedRawAssetsByClass);
        }
        for (Map.Entry entry : containedRawAssetsByClass.entrySet()) {
            Class assetClass = (Class)entry.getKey();
            Map containedAssets = (Map)entry.getValue();
            AssetStore assetStore = AssetRegistry.getAssetStore(assetClass);
            this.loadedContainedAssetsFor.add(assetClass);
            ArrayList<RawAsset<K>> childList = new ArrayList<RawAsset<K>>();
            for (Map.Entry entry3 : containedAssets.entrySet()) {
                Object key = entry3.getKey();
                for (RawAsset<Object> contained : (List)entry3.getValue()) {
                    Object containedKey = contained.getKey();
                    this.childAssetsMap.computeIfAbsent(assetStore.getAssetClass(), k -> new ConcurrentHashMap()).computeIfAbsent(key, k -> ConcurrentHashMap.newKeySet()).add(containedKey);
                    RawAsset<Object> resolvedContained = switch (contained.getContainedAssetMode()) {
                        default -> throw new MatchException(null, null);
                        case ContainedAssetCodec.Mode.NONE, ContainedAssetCodec.Mode.GENERATE_ID, ContainedAssetCodec.Mode.INJECT_PARENT, ContainedAssetCodec.Mode.INHERIT_ID -> contained;
                        case ContainedAssetCodec.Mode.INHERIT_ID_AND_PARENT -> {
                            Object parentKey = contained.getParentKey();
                            if (parentKey == null) {
                                yield contained;
                            }
                            if (((AssetMap)assetStore.getAssetMap()).getAsset(parentKey) != null || containedAssets.containsKey(parentKey)) {
                                yield contained;
                            }
                            this.logger.at(Level.WARNING).log("Failed to find inherited parent asset %s (%s) for %s", parentKey, assetStore.getAssetClass().getSimpleName(), containedKey);
                            yield contained.withResolveKeys(containedKey, null);
                        }
                    };
                    childList.add(resolvedContained);
                }
            }
            AssetLoadResult assetLoadResult = assetStore.loadBuffersWithKeys(packKey, childList, query, forceLoadAll);
            childAssetsResults.put(assetClass, assetLoadResult);
        }
    }

    protected void decodeAssets(@Nonnull String packKey, @Nonnull List<RawAsset<K>> rawAssets, @Nonnull Map<K, T> loadedAssets, @Nonnull Map<K, Path> loadedKeyToPathMap, @Nonnull Map<K, Set<K>> loadedAssetChildren, @Nonnull Set<K> failedToLoadKeys, @Nonnull Set<Path> failedToLoadPaths, @Nullable M assetMap, @Nonnull AssetUpdateQuery query, boolean forceLoadAll) {
        if (rawAssets.isEmpty()) {
            return;
        }
        ConcurrentHashMap waitingForParent = new ConcurrentHashMap();
        CompletableFuture[] futuresArr = new CompletableFuture[rawAssets.size()];
        for (int i = 0; i < rawAssets.size(); ++i) {
            futuresArr[i] = this.executeAssetDecode(loadedAssets, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, assetMap, query, forceLoadAll, waitingForParent, rawAssets.get(i));
        }
        CompletableFuture.allOf(futuresArr).join();
        for (CompletableFuture future : futuresArr) {
            DecodedAsset decodedAsset = future.getNow(null);
            if (decodedAsset == null) continue;
            loadedAssets.put(decodedAsset.getKey(), (JsonAssetWithMap)decodedAsset.getAsset());
        }
        ArrayList<CompletableFuture<DecodedAsset>> futures = new ArrayList<CompletableFuture<DecodedAsset>>();
        while (!waitingForParent.isEmpty()) {
            Object parentKey;
            int processedAssets = 0;
            for (Map.Entry entry : waitingForParent.entrySet()) {
                Object k = entry.getKey();
                RawAsset rawAsset = (RawAsset)entry.getValue();
                Path path = rawAsset.getPath();
                parentKey = rawAsset.getParentKey();
                JsonAssetWithMap parent = (JsonAssetWithMap)loadedAssets.get(parentKey);
                if (parent == null) {
                    if (waitingForParent.containsKey(parentKey)) continue;
                    if (assetMap == null) {
                        this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, k, path);
                        this.logger.at(Level.SEVERE).log("Failed to find parent '%s' for asset: %s, %s (assetMap was null)", parentKey, k, path);
                        continue;
                    }
                    JsonAssetWithMap jsonAssetWithMap = parent = parentKey.equals("super") ? (JsonAssetWithMap)((AssetMap)assetMap).getAsset(packKey, k) : (JsonAssetWithMap)((AssetMap)assetMap).getAsset(parentKey);
                    if (parent == null) {
                        this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, k, path);
                        this.logger.at(Level.SEVERE).log("Failed to find parent '%s' for asset: %s,  %s", parentKey, k, path);
                        continue;
                    }
                }
                if (this.isUnknown.test(parent)) {
                    this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, k, path);
                    this.logger.at(Level.SEVERE).log("Parent '%s' for asset: %s,  %s is an unknown type", parentKey, k, path);
                    continue;
                }
                ++processedAssets;
                JsonAssetWithMap finalParent = parent;
                futures.add(CompletableFuture.supplyAsync(() -> {
                    RawJsonReader reader;
                    char[] buffer = RawJsonReader.READ_BUFFER.get();
                    if (rawAsset.getBuffer() != null) {
                        reader = RawJsonReader.fromBuffer(rawAsset.getBuffer());
                    } else {
                        try {
                            reader = RawJsonReader.fromPath(path, buffer);
                        }
                        catch (IOException e) {
                            ((HytaleLogger.Api)this.logger.at(Level.SEVERE).withCause(e)).log("Failed to load asset: %s", path);
                            return null;
                        }
                    }
                    DecodedAsset<K, JsonAssetWithMap> decodedAsset = null;
                    try {
                        decodedAsset = this.decodeAssetWithParent0(loadedAssets, loadedKeyToPathMap, loadedAssetChildren, failedToLoadKeys, failedToLoadPaths, assetMap, query, forceLoadAll, rawAsset, reader, finalParent);
                    }
                    finally {
                        try {
                            if (rawAsset.getBuffer() != null) {
                                reader.close();
                            } else {
                                char[] value = reader.closeAndTakeBuffer();
                                if (value.length > buffer.length) {
                                    RawJsonReader.READ_BUFFER.set(value);
                                }
                            }
                        }
                        catch (IOException e) {
                            ((HytaleLogger.Api)this.logger.at(Level.SEVERE).withCause(e)).log("Failed to close asset reader: %s", path);
                        }
                        if (decodedAsset == null) {
                            waitingForParent.remove(key);
                        }
                    }
                    return decodedAsset;
                }));
            }
            CompletableFuture[] futuresArray = (CompletableFuture[])futures.toArray(CompletableFuture[]::new);
            CompletableFuture.allOf(futuresArray).join();
            futures.clear();
            for (CompletableFuture future : futuresArray) {
                DecodedAsset decodedAsset = future.getNow(null);
                if (decodedAsset == null) continue;
                loadedAssets.put(decodedAsset.getKey(), (JsonAssetWithMap)decodedAsset.getAsset());
                waitingForParent.remove(decodedAsset.getKey());
            }
            if (processedAssets != 0) continue;
            for (Map.Entry entry : waitingForParent.entrySet()) {
                Object key = entry.getKey();
                Path assetPath = ((RawAsset)entry.getValue()).getPath();
                parentKey = ((RawAsset)entry.getValue()).getParentKey();
                this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, key, assetPath);
                this.logger.at(Level.SEVERE).log("Failed to find parent with key '%s' for asset: %s, %s", parentKey, key, assetPath);
            }
        }
    }

    @Nonnull
    private CompletableFuture<DecodedAsset<K, T>> executeAssetDecode(@Nonnull Map<K, T> loadedAssets, @Nonnull Map<K, Path> loadedKeyToPathMap, @Nonnull Set<K> failedToLoadKeys, @Nonnull Set<Path> failedToLoadPaths, M assetMap, @Nonnull AssetUpdateQuery query, boolean forceLoadAll, @Nonnull Map<K, RawAsset<K>> waitingForParent, @Nonnull RawAsset<K> rawAsset) {
        return CompletableFuture.supplyAsync(() -> {
            AssetHolder<K> holder;
            RawJsonReader reader;
            try {
                reader = rawAsset.toRawJsonReader(RawJsonReader.READ_BUFFER::get);
            }
            catch (IOException e) {
                ((HytaleLogger.Api)this.logger.at(Level.SEVERE).withCause(e)).log("Failed to load asset: %s", rawAsset);
                return null;
            }
            try {
                holder = this.decodeAsset0(loadedAssets, loadedKeyToPathMap, failedToLoadKeys, failedToLoadPaths, assetMap, query, forceLoadAll, rawAsset, reader);
                if (holder instanceof RawAsset) {
                    RawAsset waiting = (RawAsset)holder;
                    waitingForParent.put(waiting.getKey(), waiting);
                }
            }
            finally {
                try {
                    if (rawAsset.getBuffer() != null) {
                        reader.close();
                    } else {
                        char[] value = reader.closeAndTakeBuffer();
                        if (value.length > RawJsonReader.READ_BUFFER.get().length) {
                            RawJsonReader.READ_BUFFER.set(value);
                        }
                    }
                }
                catch (IOException e) {
                    ((HytaleLogger.Api)this.logger.at(Level.SEVERE).withCause(e)).log("Failed to close asset reader: %s", this.path);
                }
            }
            return holder instanceof DecodedAsset ? (DecodedAsset)holder : null;
        });
    }

    @Nullable
    private AssetHolder<K> decodeAsset0(@Nonnull Map<K, T> loadedAssets, @Nonnull Map<K, Path> loadedKeyToPathMap, @Nonnull Set<K> failedToLoadKeys, @Nonnull Set<Path> failedToLoadPaths, @Nullable M assetMap, @Nonnull AssetUpdateQuery query, boolean forceLoadAll, @Nonnull RawAsset<K> rawAsset, @Nonnull RawJsonReader reader) {
        Path assetPath = rawAsset.getPath();
        long start = System.nanoTime();
        Object key = rawAsset.getKey();
        Object parentKey = rawAsset.getParentKey();
        try {
            KeyedCodec<K> keyCodec = this.codec.getKeyCodec();
            KeyedCodec<K> parentCodec = this.codec.getParentCodec();
            if (key == null) {
                if (rawAsset.getPath() != null) {
                    throw new IllegalArgumentException("Asset with path should infer its 'Id'!");
                }
                reader.mark();
                if (parentCodec != null && !rawAsset.isParentKeyResolved()) {
                    String s = RawJsonReader.seekToKeyFromObjectStart(reader, keyCodec.getKey(), parentCodec.getKey());
                    if (s != null) {
                        if (keyCodec.getKey().equals(s)) {
                            key = keyCodec.getChildCodec().decodeJson(reader);
                        } else if (parentCodec.getKey().equals(s)) {
                            parentKey = parentCodec.getChildCodec().decodeJson(reader);
                        }
                        s = RawJsonReader.seekToKeyFromObjectContinued(reader, keyCodec.getKey(), parentCodec.getKey());
                        if (s != null) {
                            if (keyCodec.getKey().equals(s)) {
                                key = keyCodec.getChildCodec().decodeJson(reader);
                            } else if (parentCodec.getKey().equals(s)) {
                                parentKey = parentCodec.getChildCodec().decodeJson(reader);
                            }
                        }
                    }
                } else if (RawJsonReader.seekToKey(reader, keyCodec.getKey())) {
                    key = keyCodec.getChildCodec().decodeJson(reader);
                }
                if (key == null) {
                    throw new CodecException("Unable to find 'Id' in document!");
                }
                reader.reset();
            } else if (parentCodec != null && !rawAsset.isParentKeyResolved()) {
                reader.mark();
                if (RawJsonReader.seekToKey(reader, parentCodec.getKey())) {
                    parentKey = parentCodec.getChildCodec().decodeJson(reader);
                }
                reader.reset();
            }
            if (assetPath == null) {
                assetPath = loadedKeyToPathMap.get(key);
            }
            if (parentKey != null) {
                return rawAsset.withResolveKeys(key, parentKey);
            }
            AssetExtraInfo extraInfo = new AssetExtraInfo(assetPath, rawAsset.makeData(this.getAssetClass(), key, null));
            reader.consumeWhiteSpace();
            JsonAssetWithMap asset = (JsonAssetWithMap)this.codec.decodeJsonAsset(reader, extraInfo);
            if (asset == null) {
                throw new NullPointerException(rawAsset.toString());
            }
            extraInfo.getValidationResults().logOrThrowValidatorExceptions(this.logger, "Failed to validate asset!\n", assetPath == null ? rawAsset.getParentPath() : assetPath, rawAsset.getLineOffset());
            if (!(DISABLE_ASSET_COMPARE || query != null && query.isDisableAssetCompare() || assetMap == null || !asset.equals(((AssetMap)assetMap).getAsset(key)))) {
                this.logger.at(Level.INFO).log("Skipping asset that hasn't changed: %s", key);
                return null;
            }
            this.testKeyFormat(key, assetPath);
            if (!forceLoadAll) {
                // empty if block
            }
            if (assetPath != null) {
                loadedKeyToPathMap.put(key, assetPath);
            }
            this.logUnusedKeys(key, assetPath, extraInfo);
            this.logLoadedAsset(key, null, assetPath);
            return new DecodedAsset<K, JsonAssetWithMap>(key, asset);
        }
        catch (CodecValidationException e) {
            this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, key, assetPath);
            this.logger.at(Level.SEVERE).log("Failed to validate asset: %s, %s, %s", key, assetPath, e.getMessage());
        }
        catch (CodecException | IOException e) {
            this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, key, assetPath);
            if (GithubMessageUtil.isGithub()) {
                Object message;
                String pathStr;
                String string = assetPath == null ? (key == null ? "unknown" : key.toString()) : (pathStr = assetPath.toString());
                if (e instanceof CodecException) {
                    CodecException codecException = (CodecException)e;
                    message = codecException.getMessage();
                    if (codecException.getCause() != null) {
                        message = (String)message + "\nCause: " + codecException.getCause().getMessage();
                    }
                } else {
                    message = e.getMessage();
                }
                if (reader.getLine() == -1) {
                    HytaleLoggerBackend.rawLog(GithubMessageUtil.messageError(pathStr, (String)message));
                } else {
                    HytaleLoggerBackend.rawLog(GithubMessageUtil.messageError(pathStr, reader.getLine(), reader.getColumn(), (String)message));
                }
            }
            ((HytaleLogger.Api)this.logger.at(Level.SEVERE).withCause(new SkipSentryException(e))).log("Failed to decode asset: %s, %s:\n%s", key, assetPath, reader);
        }
        catch (Throwable e) {
            this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, key, assetPath);
            if (GithubMessageUtil.isGithub()) {
                String pathStr = assetPath == null ? (key == null ? "unknown" : key.toString()) : assetPath.toString();
                String message = e.getMessage();
                HytaleLoggerBackend.rawLog(GithubMessageUtil.messageError(pathStr, message));
            }
            ((HytaleLogger.Api)this.logger.at(Level.SEVERE).withCause(e)).log("Failed to decode asset: %s, %s", key, (Object)assetPath);
        }
        return null;
    }

    @Nullable
    private DecodedAsset<K, T> decodeAssetWithParent0(@Nonnull Map<K, T> loadedAssets, @Nonnull Map<K, Path> loadedKeyToPathMap, @Nonnull Map<K, Set<K>> loadedAssetChildren, @Nonnull Set<K> failedToLoadKeys, @Nonnull Set<Path> failedToLoadPaths, @Nullable M assetMap, @Nonnull AssetUpdateQuery query, boolean forceLoadAll, @Nonnull RawAsset<K> rawAsset, @Nonnull RawJsonReader reader, T parent) {
        K key = rawAsset.getKey();
        if (!rawAsset.isParentKeyResolved()) {
            throw new IllegalArgumentException("Parent key is required when decoding an asset with a parent!");
        }
        K parentKey = rawAsset.getParentKey();
        Path assetPath = rawAsset.getPath();
        try {
            if (assetPath == null) {
                assetPath = loadedKeyToPathMap.get(key);
            }
            AssetExtraInfo extraInfo = new AssetExtraInfo(assetPath, rawAsset.makeData(this.getAssetClass(), key, parentKey));
            reader.consumeWhiteSpace();
            JsonAssetWithMap asset = (JsonAssetWithMap)this.codec.decodeAndInheritJsonAsset(reader, parent, extraInfo);
            if (asset == null) {
                throw new NullPointerException(assetPath.toString());
            }
            extraInfo.getValidationResults().logOrThrowValidatorExceptions(this.logger);
            if (key.equals(parentKey)) {
                this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, key, assetPath);
                this.logger.at(Level.SEVERE).log("Failed to load asset '%s' because it is its own parent!", key);
                return null;
            }
            if (!(DISABLE_ASSET_COMPARE || query != null && query.isDisableAssetCompare() || assetMap == null || !asset.equals(((AssetMap)assetMap).getAsset(key)))) {
                this.logger.at(Level.INFO).log("Skipping asset that hasn't changed: %s", key);
                return null;
            }
            this.testKeyFormat(key, assetPath);
            if (!forceLoadAll) {
                // empty if block
            }
            loadedAssetChildren.computeIfAbsent(parentKey, k -> ConcurrentHashMap.newKeySet()).add(key);
            if (assetPath != null) {
                loadedKeyToPathMap.put(key, assetPath);
            }
            this.logUnusedKeys(key, assetPath, extraInfo);
            this.logLoadedAsset(key, parentKey, assetPath);
            return new DecodedAsset<K, JsonAssetWithMap>(key, asset);
        }
        catch (CodecValidationException e) {
            this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, key, assetPath);
            this.logger.at(Level.SEVERE).log("Failed to decode asset: %s, %s, %s", key, assetPath, e.getMessage());
        }
        catch (CodecException | IOException e) {
            this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, key, assetPath);
            ((HytaleLogger.Api)this.logger.at(Level.SEVERE).withCause(new SkipSentryException(e))).log("Failed to decode asset: %s, %s:\n%s", key, assetPath, reader);
        }
        catch (Exception e) {
            this.recordFailedToLoad(failedToLoadKeys, failedToLoadPaths, key, assetPath);
            ((HytaleLogger.Api)this.logger.at(Level.SEVERE).withCause(e)).log("Failed to decode asset: %s, %s", key, (Object)assetPath);
        }
        return null;
    }

    private void loadAllChildren(@Nonnull Map<K, T> loadedAssets, @Nonnull Collection<T> assetKeys, @Nonnull Set<Path> documents) {
        for (JsonAssetWithMap asset : assetKeys) {
            Objects.requireNonNull(asset, "asset can't be null");
            K key = this.keyFunction.apply(asset);
            if (key == null) {
                throw new NullPointerException(String.format("key can't be null: %s", asset));
            }
            loadedAssets.put(key, asset);
            if (!this.loadAllChildren(documents, key)) continue;
            StringBuilder sb = new StringBuilder();
            sb.append(key).append(":\n");
            this.logChildTree(sb, "  ", key, new HashSet());
            this.logger.at(Level.SEVERE).log("Found a circular dependency when trying to collect all children!\n%s", sb);
        }
    }

    protected boolean loadAllChildren(@Nonnull Set<Path> documents, K key) {
        Set<K> set = ((AssetMap)this.assetMap).getChildren(key);
        if (set == null) {
            return false;
        }
        boolean circular = false;
        for (K child : set) {
            Path childPath = ((AssetMap)this.assetMap).getPath(child);
            if (childPath == null) continue;
            if (documents.add(childPath)) {
                circular |= this.loadAllChildren(documents, child);
                continue;
            }
            circular = true;
        }
        return circular;
    }

    protected void collectAllChildren(K key, @Nonnull Set<K> children) {
        if (this.collectAllChildren0(key, children)) {
            StringBuilder sb = new StringBuilder();
            sb.append(key).append(":\n");
            this.logChildTree(sb, "  ", key, new HashSet());
            this.logger.at(Level.SEVERE).log("Found a circular dependency when trying to collect all children!\n%s", sb);
        }
    }

    private boolean collectAllChildren0(K key, @Nonnull Set<K> children) {
        Set<K> set = ((AssetMap)this.assetMap).getChildren(key);
        if (set == null) {
            return false;
        }
        boolean circular = false;
        for (K child : set) {
            if (children.add(child)) {
                circular |= this.collectAllChildren0(child, children);
                continue;
            }
            circular = true;
        }
        return circular;
    }

    protected void logChildTree(@Nonnull StringBuilder sb, String indent, K key, @Nonnull Set<K> children) {
        Set<K> set = ((AssetMap)this.assetMap).getChildren(key);
        if (set == null) {
            return;
        }
        for (K child : set) {
            if (children.add(child)) {
                sb.append(indent).append("- ").append(child).append('\n');
                this.logChildTree(sb, indent + "  ", child, children);
                continue;
            }
            sb.append(indent).append("- ").append(child).append('\n').append(indent).append("  ").append("** Circular **\n");
        }
    }

    protected void logRemoveChildren(K parentKey, @Nonnull Set<K> toBeRemoved) {
        Path path = ((AssetMap)this.assetMap).getPath(parentKey);
        for (K child : toBeRemoved) {
            Path childPath = ((AssetMap)this.assetMap).getPath(child);
            if (childPath != null) {
                if (path != null) {
                    this.logger.at(Level.WARNING).log("Removing child asset '%s' of removed asset '%s'", (Object)childPath, (Object)path);
                    continue;
                }
                this.logger.at(Level.WARNING).log("Removing child asset '%s' of removed asset '%s'", (Object)childPath, parentKey);
                continue;
            }
            this.logger.at(Level.WARNING).log("Removing child asset '%s' of removed asset '%s'", child, parentKey);
        }
    }

    protected void logRemoveChildren(@Nonnull Map<K, K> toBeRemoved) {
        for (Map.Entry<K, K> entry : toBeRemoved.entrySet()) {
            K child = entry.getKey();
            K parentKey = entry.getValue();
            Path childPath = ((AssetMap)this.assetMap).getPath(child);
            if (childPath != null) {
                Path path = ((AssetMap)this.assetMap).getPath(parentKey);
                if (path != null) {
                    this.logger.at(Level.WARNING).log("Removing child asset '%s' of removed asset '%s'", (Object)childPath, (Object)path);
                    continue;
                }
                this.logger.at(Level.WARNING).log("Removing child asset '%s' of removed asset '%s'", (Object)childPath, parentKey);
                continue;
            }
            this.logger.at(Level.WARNING).log("Removing child asset '%s' of removed asset '%s'", child, parentKey);
        }
    }

    protected void testKeyFormat(@Nonnull K key, @Nullable Path assetPath) {
        String keyStr = key.toString();
        if (StringUtil.isCapitalized(keyStr, '_')) {
            return;
        }
        String expected = StringUtil.capitalize(keyStr, '_');
        if (assetPath == null) {
            this.logger.at(Level.WARNING).log("Asset key '%s' has incorrect format! Expected: '%s'", key, (Object)expected);
        } else {
            this.logger.at(Level.WARNING).log("Asset key '%s' for file '%s' has incorrect format! Expected: '%s'", key, assetPath, expected);
        }
    }

    public void logUnusedKeys(@Nonnull K key, @Nullable Path assetPath, @Nonnull AssetExtraInfo<K> extraInfo) {
        List<String> unknownKeys = extraInfo.getUnknownKeys();
        if (!unknownKeys.isEmpty()) {
            if (GithubMessageUtil.isGithub()) {
                String pathStr = assetPath == null ? key.toString() : assetPath.toString();
                for (int i = 0; i < unknownKeys.size(); ++i) {
                    String unknownKey = unknownKeys.get(i);
                    HytaleLoggerBackend.rawLog(GithubMessageUtil.messageWarning(pathStr, "Unused key: " + unknownKey));
                }
            } else if (assetPath != null) {
                this.logger.at(Level.WARNING).log("Unused key(s) in '%s' file %s: %s", key, assetPath, String.join((CharSequence)", ", unknownKeys));
            } else {
                this.logger.at(Level.WARNING).log("Unused key(s) in '%s': %s", key, (Object)String.join((CharSequence)", ", unknownKeys));
            }
        }
    }

    protected void logLoadedAsset(K key, @Nullable K parentKey, @Nullable Path path) {
        if (path == null && parentKey == null) {
            this.logger.at(Level.FINE).log("Loaded asset: %s", key);
        } else if (path == null) {
            this.logger.at(Level.FINE).log("Loaded asset: '%s' with parent '%s'", key, parentKey);
        } else if (parentKey == null) {
            this.logger.at(Level.FINE).log("Loaded asset: '%s' from '%s'", key, (Object)path);
        } else {
            this.logger.at(Level.FINE).log("Loaded asset: '%s' from '%s' with parent '%s'", key, path, parentKey);
        }
    }

    protected void logRemoveAsset(K key, @Nullable Path path) {
        if (path == null) {
            this.logger.at(Level.FINE).log("Removed asset: '%s'", key);
        } else {
            this.logger.at(Level.FINE).log("Removed asset: '%s' from '%s'", key, (Object)path);
        }
    }

    private void recordFailedToLoad(@Nonnull Set<K> failedToLoadKeys, @Nonnull Set<Path> failedToLoadPaths, @Nullable K key, @Nullable Path path) {
        if (key != null) {
            failedToLoadKeys.add(key);
        }
        if (path != null) {
            failedToLoadPaths.add(path);
        }
    }

    @Nonnull
    public String toString() {
        return "AssetStore{tClass=" + String.valueOf(this.tClass) + "}";
    }

    protected static abstract class Builder<K, T extends JsonAssetWithMap<K, M>, M extends AssetMap<K, T>, B extends Builder<K, T, M, B>> {
        @Nonnull
        protected final Class<K> kClass;
        @Nonnull
        protected final Class<T> tClass;
        protected final M assetMap;
        protected final Set<Class<? extends JsonAsset<?>>> loadsAfter = new HashSet();
        protected final Set<Class<? extends JsonAsset<?>>> loadsBefore = new HashSet();
        protected String path;
        @Nonnull
        protected String extension = ".json";
        protected AssetCodec<K, T> codec;
        protected Function<T, K> keyFunction;
        protected Function<K, T> replaceOnRemove;
        protected Predicate<T> isUnknown;
        protected boolean unmodifiable;
        protected List<T> preAddedAssets;
        protected Class<? extends JsonAsset<?>> idProvider;

        public Builder(Class<K> kClass, Class<T> tClass, M assetMap) {
            this.kClass = Objects.requireNonNull(kClass, "key class can't be null!");
            this.tClass = Objects.requireNonNull(tClass, "asset class can't be null!");
            this.assetMap = assetMap;
        }

        @Nonnull
        public B setPath(String path) {
            this.path = Objects.requireNonNull(path, "path can't be null!");
            return (B)this;
        }

        @Nonnull
        public B setExtension(@Nonnull String extension) {
            Objects.requireNonNull(extension, "extension can't be null!");
            if (extension.length() < 2 || extension.charAt(0) != '.') {
                throw new IllegalArgumentException("Extension must start with '.' and have at least one character after");
            }
            this.extension = extension;
            return (B)this;
        }

        @Nonnull
        public B setCodec(AssetCodec<K, T> codec) {
            this.codec = Objects.requireNonNull(codec, "codec can't be null!");
            return (B)this;
        }

        @Nonnull
        public B setKeyFunction(Function<T, K> keyFunction) {
            this.keyFunction = Objects.requireNonNull(keyFunction, "keyFunction can't be null!");
            return (B)this;
        }

        @Nonnull
        public B setIsUnknown(Predicate<T> isUnknown) {
            this.isUnknown = Objects.requireNonNull(isUnknown, "isUnknown can't be null!");
            return (B)this;
        }

        @Nonnull
        @SafeVarargs
        public final B loadsAfter(Class<? extends JsonAsset<?>> ... clazz) {
            Collections.addAll(this.loadsAfter, clazz);
            return (B)this;
        }

        @Nonnull
        @SafeVarargs
        public final B loadsBefore(Class<? extends JsonAsset<?>> ... clazz) {
            Collections.addAll(this.loadsBefore, clazz);
            return (B)this;
        }

        @Nonnull
        public B setReplaceOnRemove(Function<K, T> replaceOnRemove) {
            this.replaceOnRemove = Objects.requireNonNull(replaceOnRemove, "replaceOnRemove can't be null!");
            return (B)this;
        }

        @Nonnull
        public B unmodifiable() {
            this.unmodifiable = true;
            return (B)this;
        }

        @Nonnull
        public B preLoadAssets(@Nonnull List<T> list) {
            if (this.preAddedAssets == null) {
                this.preAddedAssets = new ArrayList<T>();
            }
            this.preAddedAssets.addAll(list);
            return (B)this;
        }

        @Nonnull
        public B setIdProvider(Class<? extends JsonAsset<?>> provider) {
            this.idProvider = provider;
            return (B)this;
        }

        public abstract AssetStore<K, T, M> build();
    }
}

