/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.common;

import com.hypixel.hytale.assetstore.AssetPack;
import com.hypixel.hytale.common.plugin.PluginManifest;
import com.hypixel.hytale.common.util.ArrayUtil;
import com.hypixel.hytale.common.util.FormatUtil;
import com.hypixel.hytale.common.util.PathUtil;
import com.hypixel.hytale.common.util.PatternUtil;
import com.hypixel.hytale.event.IEventDispatcher;
import com.hypixel.hytale.function.supplier.CachedSupplier;
import com.hypixel.hytale.function.supplier.SupplierUtil;
import com.hypixel.hytale.logger.HytaleLogger;
import com.hypixel.hytale.logger.sentry.SkipSentryException;
import com.hypixel.hytale.math.util.MathUtil;
import com.hypixel.hytale.protocol.Asset;
import com.hypixel.hytale.protocol.Packet;
import com.hypixel.hytale.protocol.packets.interface_.Notification;
import com.hypixel.hytale.protocol.packets.interface_.NotificationStyle;
import com.hypixel.hytale.protocol.packets.setup.AssetFinalize;
import com.hypixel.hytale.protocol.packets.setup.AssetInitialize;
import com.hypixel.hytale.protocol.packets.setup.AssetPart;
import com.hypixel.hytale.protocol.packets.setup.RemoveAssets;
import com.hypixel.hytale.protocol.packets.setup.RequestCommonAssetsRebuild;
import com.hypixel.hytale.protocol.packets.setup.WorldLoadProgress;
import com.hypixel.hytale.server.core.HytaleServer;
import com.hypixel.hytale.server.core.Message;
import com.hypixel.hytale.server.core.asset.AssetModule;
import com.hypixel.hytale.server.core.asset.AssetPackRegisterEvent;
import com.hypixel.hytale.server.core.asset.AssetPackUnregisterEvent;
import com.hypixel.hytale.server.core.asset.LoadAssetEvent;
import com.hypixel.hytale.server.core.asset.common.BlockyAnimationCache;
import com.hypixel.hytale.server.core.asset.common.CommonAsset;
import com.hypixel.hytale.server.core.asset.common.CommonAssetRegistry;
import com.hypixel.hytale.server.core.asset.common.asset.FileCommonAsset;
import com.hypixel.hytale.server.core.asset.common.events.CommonAssetMonitorEvent;
import com.hypixel.hytale.server.core.asset.common.events.SendCommonAssetsEvent;
import com.hypixel.hytale.server.core.asset.monitor.AssetMonitor;
import com.hypixel.hytale.server.core.asset.monitor.AssetMonitorHandler;
import com.hypixel.hytale.server.core.asset.monitor.EventKind;
import com.hypixel.hytale.server.core.io.PacketHandler;
import com.hypixel.hytale.server.core.plugin.JavaPlugin;
import com.hypixel.hytale.server.core.plugin.JavaPluginInit;
import com.hypixel.hytale.server.core.universe.Universe;
import com.hypixel.hytale.server.core.util.NotificationUtil;
import com.hypixel.hytale.server.core.util.io.FileUtil;
import com.hypixel.hytale.sneakythrow.SneakyThrow;
import it.unimi.dsi.fastutil.booleans.BooleanObjectPair;
import it.unimi.dsi.fastutil.objects.ObjectArrayList;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class CommonAssetModule
extends JavaPlugin {
    public static final PluginManifest MANIFEST = PluginManifest.corePlugin(CommonAssetModule.class).depends(AssetModule.class).build();
    private static CommonAssetModule instance;
    public static final Set<Path> IGNORED_FILES;
    public static final Instant TICK_TIMESTAMP_ORIGIN;
    public static final String ASSET_INDEX_VERSION_IDENTIFIER = "VERSION=";
    public static final int ASSET_INDEX_HASHES_VERSION = 0;
    public static final int ASSET_INDEX_CACHE_VERSION = 1;
    public static final int MAX_FRAME = 0x280000;
    private final CachedSupplier<Asset[]> assets = SupplierUtil.cache(() -> (Asset[])CommonAssetRegistry.getAllAssets().stream().map(List::getLast).map(CommonAssetRegistry.PackAsset::asset).map(CommonAsset::toPacket).toArray(Asset[]::new));

    public static CommonAssetModule get() {
        return instance;
    }

    public CommonAssetModule(@Nonnull JavaPluginInit init) {
        super(init);
        instance = this;
    }

    @Override
    protected void setup() {
        this.getEventRegistry().register(SendCommonAssetsEvent.class, this::onSendCommonAssets);
        this.getEventRegistry().register((short)-32, LoadAssetEvent.class, event -> {
            for (AssetPack pack : AssetModule.get().getAssetPacks()) {
                this.loadCommonAssets(pack, event.getBootStart());
            }
        });
        this.getEventRegistry().register((short)-32, AssetPackRegisterEvent.class, event -> this.loadCommonAssets(event.getAssetPack(), System.nanoTime()));
        this.getEventRegistry().register(AssetPackUnregisterEvent.class, event -> this.removeCommonAssets(event.getAssetPack()));
    }

    private void removeCommonAssets(@Nonnull AssetPack assetPack) {
        this.unregisterAssetMonitor(assetPack);
        ObjectArrayList<CommonAssetRegistry.PackAsset> removedAssets = new ObjectArrayList<CommonAssetRegistry.PackAsset>();
        ObjectArrayList<CommonAsset> updatedAssets = new ObjectArrayList<CommonAsset>();
        Collection<List<CommonAssetRegistry.PackAsset>> allAssets = CommonAssetRegistry.getAllAssets();
        for (List<CommonAssetRegistry.PackAsset> assets : allAssets) {
            for (CommonAssetRegistry.PackAsset asset : assets) {
                if (!asset.pack().equals(assetPack.getName())) continue;
                BooleanObjectPair<CommonAssetRegistry.PackAsset> removed = CommonAssetRegistry.removeCommonAssetByName(asset.pack(), asset.asset().getName());
                if (removed != null) {
                    if (removed.firstBoolean()) {
                        updatedAssets.add(((CommonAssetRegistry.PackAsset)removed.second()).asset());
                    } else {
                        removedAssets.add((CommonAssetRegistry.PackAsset)removed.second());
                    }
                }
                this.assets.invalidate();
            }
        }
        this.sendRemoveAssets(removedAssets, false);
        this.sendAssets(updatedAssets, false);
        Universe.get().broadcastPacketNoCache(new RequestCommonAssetsRebuild());
    }

    public void loadCommonAssets(@Nonnull AssetPack pack, long bootTime) {
        Path assetPath = pack.getRoot();
        HytaleLogger.getLogger().at(Level.INFO).log("Loading common assets from: %s", assetPath);
        long start = System.nanoTime();
        if (this.readCommonAssetsIndexHashes(pack)) {
            int duplicateAssetCount = CommonAssetRegistry.getDuplicateAssetCount();
            if (duplicateAssetCount > 0) {
                this.getLogger().at(Level.WARNING).log("Duplicated Asset Count: %s", duplicateAssetCount);
            }
            HytaleLogger.getLogger().at(Level.INFO).log("Loading common assets phase completed! Boot time %s, Took %s", (Object)FormatUtil.nanosToString(System.nanoTime() - bootTime), (Object)FormatUtil.nanosToString(System.nanoTime() - start));
            return;
        }
        Path commonPath = pack.getRoot().resolve("Common");
        AssetMonitor assetMonitor = AssetModule.get().getAssetMonitor();
        if (assetMonitor != null && !pack.isImmutable() && Files.isDirectory(commonPath, new LinkOption[0])) {
            assetMonitor.monitorDirectoryFiles(commonPath, new CommonAssetMonitorHandler(pack, commonPath));
        }
        this.readCommonAssetsIndexCache(pack);
        try {
            this.walkFileTree(pack);
        }
        catch (IOException e) {
            throw SneakyThrow.sneakyThrow(e);
        }
        int duplicateAssetCount = CommonAssetRegistry.getDuplicateAssetCount();
        if (duplicateAssetCount > 0) {
            this.getLogger().at(Level.WARNING).log("Duplicated Asset Count: %s", duplicateAssetCount);
        }
        HytaleLogger.getLogger().at(Level.INFO).log("Loading common assets phase completed! Boot time %s, Took %s", (Object)FormatUtil.nanosToString(System.nanoTime() - bootTime), (Object)FormatUtil.nanosToString(System.nanoTime() - start));
        Universe.get().broadcastPacketNoCache(new RequestCommonAssetsRebuild());
    }

    public <T extends CommonAsset> void addCommonAsset(String pack, @Nonnull T asset) {
        this.addCommonAsset(pack, asset, true);
    }

    public <T extends CommonAsset> void addCommonAsset(String pack, @Nonnull T asset, boolean log) {
        CommonAssetRegistry.AddCommonAssetResult result = CommonAssetRegistry.addCommonAsset(pack, asset);
        CommonAssetRegistry.PackAsset newAsset = result.getNewPackAsset();
        CommonAssetRegistry.PackAsset oldAsset = result.getPreviousNameAsset();
        if (oldAsset != null && oldAsset.asset().getHash().equals(newAsset.asset().getHash())) {
            if (log) {
                this.getLogger().at(Level.INFO).log("Didn't change: %s", asset.getName());
            }
            return;
        }
        if (oldAsset == null) {
            if (log) {
                this.getLogger().at(Level.INFO).log("Created: %s", newAsset);
            }
        } else if (log) {
            this.getLogger().at(Level.INFO).log("Reloaded: %s - Old Hash: %s", (Object)newAsset, (Object)oldAsset.asset().getHash());
        }
        String messageId = oldAsset == null ? "server.general.assetstore.reloadAssets" : "server.general.assetstore.reloadAssets";
        String iconPath = oldAsset == null ? "Icons/AssetNotifications/IconCheckmark.png" : "Icons/AssetNotifications/AssetReloaded.png";
        String messageColor = oldAsset == null ? "#06EE92" : "#A7AfA7";
        NotificationUtil.sendNotificationToUniverse(Message.translation(messageId).color(messageColor).param("class", "Common"), Message.raw(newAsset.pack() + ":" + newAsset.asset().getName()), iconPath, NotificationStyle.Success);
        if (!result.getActiveAsset().equals(newAsset)) {
            return;
        }
        this.assets.invalidate();
        BlockyAnimationCache.invalidate(newAsset.asset().getName());
        if (Universe.get().getPlayerCount() > 0) {
            this.sendAsset(newAsset.asset(), false);
        }
    }

    @Nullable
    public Asset[] getRequiredAssets() {
        return this.assets.get();
    }

    private boolean readCommonAssetsIndexHashes(@Nonnull AssetPack pack) {
        Path assetPath = pack.getRoot();
        Path commonPath = assetPath.resolve("Common");
        Path assetHashFile = assetPath.resolve("CommonAssetsIndex.hashes");
        if (Files.isRegularFile(assetHashFile, new LinkOption[0])) {
            long loadHashesStart = System.nanoTime();
            int loadedAssetCount = 0;
            try (BufferedReader reader = Files.newBufferedReader(assetHashFile);){
                String line;
                int version = 0;
                int i = 0;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith(ASSET_INDEX_VERSION_IDENTIFIER)) {
                        version = Integer.parseInt(line.substring(ASSET_INDEX_VERSION_IDENTIFIER.length()));
                        this.getLogger().at(Level.FINEST).log("Version set to %d from CommonAssetsIndex.hashes:L%d '%s'", version, i, line);
                        if (version > 0) {
                            throw new IllegalArgumentException(String.format("Unsupported version %d in CommonAssetsIndex.hashes %d > %d", version, version, 0));
                        }
                    } else {
                        String[] split = line.split(" ", 2);
                        if (split.length != 2) {
                            this.getLogger().at(Level.WARNING).log("Corrupt line in CommonAssetsIndex.hashes:L%d '%s'", i, (Object)line);
                        } else {
                            String hash = split[0];
                            if (hash.length() != 64 && !CommonAsset.HASH_PATTERN.matcher(hash).matches()) {
                                this.getLogger().at(Level.WARNING).log("Corrupt line in CommonAssetsIndex.hashes:L%d '%s'", i, (Object)line);
                            } else {
                                String name = split[1];
                                this.addCommonAsset(pack.getName(), new FileCommonAsset(commonPath.resolve(name), name, hash, null), false);
                                this.getLogger().at(Level.FINEST).log("Loaded asset info from CommonAssetsIndex.hashes:L%d '%s'", i, (Object)name);
                                ++loadedAssetCount;
                            }
                        }
                    }
                    ++i;
                }
            }
            catch (IOException e) {
                ((HytaleLogger.Api)this.getLogger().at(Level.WARNING).withCause(e)).log("Failed to load hashes from CommonAssetsIndex.hashes");
                return false;
            }
            long loadHashesEnd = System.nanoTime();
            long loadHashesDiff = loadHashesEnd - loadHashesStart;
            this.getLogger().at(Level.INFO).log("Took %s to load %d assets from CommonAssetsIndex.hashes file.", (Object)FormatUtil.nanosToString(loadHashesDiff), loadedAssetCount);
            return true;
        }
        return false;
    }

    private void readCommonAssetsIndexCache(@Nonnull AssetPack pack) {
        Path assetPath = pack.getRoot();
        Path commonPath = assetPath.resolve("Common");
        Path assetCacheFile = assetPath.resolve("CommonAssetsIndex.cache");
        if (!Files.isRegularFile(assetCacheFile, new LinkOption[0])) {
            return;
        }
        long loadCacheStart = System.nanoTime();
        AtomicInteger loadedAssetCount = new AtomicInteger();
        ObjectArrayList futures = new ObjectArrayList();
        try (BufferedReader reader = Files.newBufferedReader(assetCacheFile);){
            String line;
            int version = 0;
            int i = 0;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(ASSET_INDEX_VERSION_IDENTIFIER)) {
                    version = Integer.parseInt(line.substring(ASSET_INDEX_VERSION_IDENTIFIER.length()));
                    this.getLogger().at(Level.FINEST).log("Version set to %d from CommonAssetsIndex.cache:L%d '%s'", version, i, line);
                    if (version > 1) {
                        throw new IllegalArgumentException(String.format("Unsupported version %d in CommonAssetsIndex.cache %d > %d", version, version, 1));
                    }
                } else {
                    int indexOne = line.indexOf(32);
                    int indexTwo = line.indexOf(32, indexOne + 1);
                    if (indexTwo < 0) {
                        this.getLogger().at(Level.WARNING).log("Corrupt line in CommonAssetsIndex.cache:L%d '%s'", i, (Object)line);
                    } else {
                        String hash = line.substring(0, indexOne);
                        if (hash.length() != 64 && !CommonAsset.HASH_PATTERN.matcher(hash).matches()) {
                            this.getLogger().at(Level.WARNING).log("Corrupt line in CommonAssetsIndex.cache:L%d '%s'", i, (Object)line);
                        } else {
                            Instant timestamp;
                            long timestampLong = Long.parseLong(line, indexOne + 1, indexTwo, 10);
                            if (version > 0) {
                                timestamp = Instant.ofEpochSecond(timestampLong);
                            } else {
                                long timestampMillis = timestampLong / 10000L;
                                timestamp = TICK_TIMESTAMP_ORIGIN.plusMillis(timestampMillis);
                            }
                            String name = line.substring(indexTwo + 1);
                            Path file = commonPath.resolve(name);
                            int lineNumber = i;
                            futures.add(CompletableFuture.supplyAsync(() -> {
                                BasicFileAttributes attributes;
                                try {
                                    attributes = Files.readAttributes(file, BasicFileAttributes.class, new LinkOption[0]);
                                }
                                catch (IOException ignored) {
                                    return null;
                                }
                                if (!attributes.isRegularFile()) {
                                    return null;
                                }
                                Instant lastModified = attributes.lastModifiedTime().toInstant().truncatedTo(ChronoUnit.SECONDS);
                                if (timestamp.equals(lastModified)) {
                                    this.addCommonAsset(pack.getName(), new FileCommonAsset(file, name, hash, null), false);
                                    this.getLogger().at(Level.FINEST).log("Loaded asset info from CommonAssetsIndex.cache:L%d '%s'", lineNumber, (Object)name);
                                    loadedAssetCount.getAndIncrement();
                                } else {
                                    this.getLogger().at(Level.FINEST).log("Skipped outdated asset from CommonAssetsIndex.cache:L%d '%s', Timestamp: %s, Last Modified: %s", lineNumber, name, timestamp, lastModified);
                                }
                                return null;
                            }));
                        }
                    }
                }
                ++i;
            }
        }
        catch (IOException e) {
            ((HytaleLogger.Api)this.getLogger().at(Level.WARNING).withCause(e)).log("Failed to load hashes from CommonAssetsIndex.cache");
        }
        CompletableFuture.allOf((CompletableFuture[])futures.toArray(CompletableFuture[]::new)).join();
        long loadCacheEnd = System.nanoTime();
        long loadCacheDiff = loadCacheEnd - loadCacheStart;
        this.getLogger().at(Level.INFO).log("Took %s to load %d assets from CommonAssetsIndex.cache file.", (Object)FormatUtil.nanosToString(loadCacheDiff), loadedAssetCount.get());
    }

    private void walkFileTree(final @Nonnull AssetPack pack) throws IOException {
        Path assetPath = pack.getRoot();
        Path commonPath = assetPath.resolve("Common").toAbsolutePath();
        if (!Files.exists(commonPath, new LinkOption[0])) {
            return;
        }
        final int commonPathSubStringIndex = commonPath.toString().length() + 1;
        long walkFileTreeStart = System.nanoTime();
        final ObjectArrayList futures = new ObjectArrayList();
        Files.walkFileTree(commonPath, FileUtil.DEFAULT_WALK_TREE_OPTIONS_SET, Integer.MAX_VALUE, (FileVisitor<? super Path>)new SimpleFileVisitor<Path>(this){
            final /* synthetic */ CommonAssetModule this$0;
            {
                this.this$0 = this$0;
            }

            @Override
            @Nonnull
            public FileVisitResult visitFile(@Nonnull Path path, @Nonnull BasicFileAttributes attrs) throws IOException {
                if (!attrs.isRegularFile()) {
                    return FileVisitResult.CONTINUE;
                }
                Path fileName = path.getFileName();
                if (IGNORED_FILES.contains(fileName)) {
                    String name = PatternUtil.replaceBackslashWithForwardSlash(path.toString().substring(commonPathSubStringIndex));
                    this.this$0.getLogger().at(Level.FINEST).log("Skipping ignored file at %s", name);
                    return FileVisitResult.CONTINUE;
                }
                if (fileName.toString().endsWith(".hash")) {
                    Files.deleteIfExists(path);
                    return FileVisitResult.CONTINUE;
                }
                String name = PatternUtil.replaceBackslashWithForwardSlash(path.toString().substring(commonPathSubStringIndex));
                if (CommonAssetRegistry.hasCommonAsset(pack, name)) {
                    return FileVisitResult.CONTINUE;
                }
                this.this$0.getLogger().at(Level.FINER).log("Loading asset: %s", name);
                futures.add(((CompletableFuture)CompletableFuture.supplyAsync(SneakyThrow.sneakySupplier(() -> Files.readAllBytes(path))).thenAcceptAsync(bytes -> {
                    FileCommonAsset asset = new FileCommonAsset(path, name, (byte[])bytes);
                    this.this$0.addCommonAsset(pack.getName(), asset, false);
                    this.this$0.getLogger().at(Level.FINER).log("Loaded asset: %s", asset);
                })).exceptionally(throwable -> {
                    ((HytaleLogger.Api)this.this$0.getLogger().at(Level.FINE).withCause((Throwable)throwable)).log("Failed to load asset: %s", name);
                    throw SneakyThrow.sneakyThrow(throwable);
                }));
                return FileVisitResult.CONTINUE;
            }
        });
        CompletableFuture.allOf((CompletableFuture[])futures.toArray(CompletableFuture[]::new)).join();
        this.assets.invalidate();
        long walkFileTreeEnd = System.nanoTime();
        long walkFileTreeDiff = walkFileTreeEnd - walkFileTreeStart;
        this.getLogger().at(Level.INFO).log("Took %s to walk file tree and load %d assets.", (Object)FormatUtil.nanosToString(walkFileTreeDiff), futures.size());
    }

    private void unregisterAssetMonitor(@Nonnull AssetPack pack) {
        AssetMonitor assetMonitor = AssetModule.get().getAssetMonitor();
        if (assetMonitor != null) {
            assetMonitor.removeMonitorDirectoryFiles(pack.getRoot().resolve("Common"), pack);
        }
    }

    private void reloadAsset(@Nonnull List<CompletableFuture<Void>> addedOrUpdatedAssets, String pack, @Nonnull Path file, @Nonnull String name) {
        this.getLogger().at(Level.FINEST).log("Reloading: %s", file);
        addedOrUpdatedAssets.add((CompletableFuture<Void>)((CompletableFuture)CompletableFuture.supplyAsync(SneakyThrow.sneakySupplier(() -> Files.readAllBytes(file))).thenAcceptAsync(bytes -> this.addCommonAsset(pack, new FileCommonAsset(file, name, (byte[])bytes)))).exceptionally(throwable -> {
            if (throwable instanceof NoSuchFileException) {
                throwable = new SkipSentryException((Throwable)throwable);
            }
            ((HytaleLogger.Api)this.getLogger().at(Level.SEVERE).withCause((Throwable)throwable)).log("Failed to reload asset: %s", file);
            return null;
        }));
    }

    private void onSendCommonAssets(@Nonnull SendCommonAssetsEvent event) {
        this.sendAssetsToPlayer(event.getPacketHandler(), event.getRequestedAssets(), true);
    }

    public void sendAssetsToPlayer(@Nonnull PacketHandler packetHandler, @Nullable Asset[] requested, boolean forceRebuild) {
        ObjectArrayList<CommonAsset> toSend = new ObjectArrayList<CommonAsset>();
        if (requested != null) {
            for (Asset toSendAsset : requested) {
                CommonAsset asset = CommonAssetRegistry.getByHash(toSendAsset.hash);
                Objects.requireNonNull(asset, toSendAsset.hash);
                toSend.add(asset);
            }
        } else {
            for (List<CommonAssetRegistry.PackAsset> asset : CommonAssetRegistry.getAllAssets()) {
                toSend.add(asset.getLast().asset());
            }
        }
        this.getLogger().at(Level.FINE).log("%s requested %d assets!", (Object)packetHandler.getIdentifier(), toSend.size());
        this.sendAssetsToPlayer(packetHandler, toSend, forceRebuild);
    }

    public void sendAssets(@Nonnull List<CommonAsset> toSend, boolean forceRebuild) {
        for (int i = 0; i < toSend.size(); ++i) {
            CommonAsset thisAsset = toSend.get(i);
            byte[] allBytes = thisAsset.getBlob().join();
            byte[][] parts = ArrayUtil.split(allBytes, 0x280000);
            Packet[] packets = new Packet[2 + parts.length];
            packets[0] = new AssetInitialize(thisAsset.toPacket(), allBytes.length);
            for (int partIndex = 0; partIndex < parts.length; ++partIndex) {
                packets[1 + partIndex] = new AssetPart(parts[partIndex]);
            }
            packets[packets.length - 1] = new AssetFinalize();
            Universe.get().broadcastPacket(packets);
        }
        if (!toSend.isEmpty() && forceRebuild) {
            Universe.get().broadcastPacketNoCache(new RequestCommonAssetsRebuild());
        }
    }

    public void sendAssetsToPlayer(@Nonnull PacketHandler packetHandler, @Nonnull List<CommonAsset> toSend, boolean forceRebuild) {
        for (int i = 0; i < toSend.size(); ++i) {
            int thisPercent = MathUtil.getPercentageOf(i, toSend.size());
            CommonAsset thisAsset = toSend.get(i);
            byte[] allBytes = thisAsset.getBlob().join();
            byte[][] parts = ArrayUtil.split(allBytes, 0x280000);
            Packet[] packets = new Packet[2 + parts.length * 2];
            packets[0] = new AssetInitialize(thisAsset.toPacket(), allBytes.length);
            for (int partIndex = 0; partIndex < parts.length; ++partIndex) {
                packets[1 + partIndex * 2] = new WorldLoadProgress("Loading asset " + thisAsset.getName(), thisPercent, 100 * partIndex / parts.length);
                packets[1 + partIndex * 2 + 1] = new AssetPart(parts[partIndex]);
            }
            packets[packets.length - 1] = new AssetFinalize();
            packetHandler.write(packets);
        }
        if (!toSend.isEmpty() && forceRebuild) {
            packetHandler.writeNoCache(new RequestCommonAssetsRebuild());
        }
    }

    public void sendAsset(@Nonnull CommonAsset asset, boolean forceRebuild) {
        asset.getBlob().whenComplete((allBytes, throwable) -> {
            if (throwable != null) {
                this.getLogger().at(Level.WARNING).log("Failed to send asset: %s, %s", (Object)asset.getName(), (Object)asset.getHash());
            } else {
                byte[][] parts = ArrayUtil.split(allBytes, 0x280000);
                Packet[] packets = new Packet[2 + (forceRebuild ? 1 : 0) + parts.length];
                packets[0] = new AssetInitialize(asset.toPacket(), ((byte[])allBytes).length);
                for (int i = 0; i < parts.length; ++i) {
                    packets[1 + i] = new AssetPart(parts[i]);
                }
                packets[1 + parts.length] = new AssetFinalize();
                if (forceRebuild) {
                    packets[2 + parts.length] = new RequestCommonAssetsRebuild();
                }
                Universe.get().broadcastPacket(packets);
            }
        });
    }

    public void sendRemoveAssets(@Nonnull List<CommonAssetRegistry.PackAsset> assets, boolean forceRebuild) {
        int size = assets.size();
        Asset[] asset_ = new Asset[size];
        String messageRemovalKey = "server.general.assetstore.removedAssets";
        String color = "#FF3874";
        String icon = "Icons/AssetNotifications/Trash.png";
        Message message = Message.translation("server.general.assetstore.removedAssets").param("class", "Common").color("#FF3874");
        int packetCountThreshold = 5;
        int packetsCount = 1 + (forceRebuild ? 1 : 0) + (assets.size() < 5 ? assets.size() : 1);
        Packet[] packets = new Packet[packetsCount];
        int i = 0;
        for (CommonAssetRegistry.PackAsset asset : assets) {
            asset_[i++] = asset.asset().toPacket();
        }
        if (assets.size() < 5) {
            i = 0;
            for (CommonAssetRegistry.PackAsset asset : assets) {
                Message assetName = Message.raw(asset.pack() + ":" + asset.asset().getName()).color("#FF3874");
                packets[i++] = new Notification(message.getFormattedMessage(), assetName.getFormattedMessage(), "Icons/AssetNotifications/Trash.png", null, NotificationStyle.Default);
            }
            packets[i++] = new RemoveAssets(asset_);
            if (forceRebuild) {
                packets[i++] = new RequestCommonAssetsRebuild();
            }
        } else {
            Message secondaryMessage = Message.translation("server.general.assetstore.removedAssetsSecondaryGeneric").param("count", assets.size());
            packets[0] = new Notification(message.getFormattedMessage(), secondaryMessage.getFormattedMessage(), "Icons/AssetNotifications/Trash.png", null, NotificationStyle.Default);
            packets[1] = new RemoveAssets(asset_);
            if (forceRebuild) {
                packets[2] = new RequestCommonAssetsRebuild();
            }
        }
        Universe.get().broadcastPacket(packets);
    }

    static {
        IGNORED_FILES = Set.of(Path.of(".DS_Store", new String[0]), Path.of("Thumbs.db", new String[0]));
        TICK_TIMESTAMP_ORIGIN = Instant.parse("0001-01-01T00:00:00Z");
    }

    private class CommonAssetMonitorHandler
    implements AssetMonitorHandler {
        private final AssetPack pack;
        private final Path commonPath;

        public CommonAssetMonitorHandler(AssetPack pack, Path commonPath) {
            this.pack = pack;
            this.commonPath = commonPath;
        }

        @Override
        public Object getKey() {
            return this.pack;
        }

        @Override
        public boolean test(Path path, EventKind eventKind) {
            return !IGNORED_FILES.contains(path.getFileName());
        }

        @Override
        public void accept(Map<Path, EventKind> map) {
            String name;
            IEventDispatcher<CommonAssetMonitorEvent, CommonAssetMonitorEvent> dispatchFor;
            ObjectArrayList<Path> createdOrModifiedFilesToLoad = new ObjectArrayList<Path>();
            ObjectArrayList<Path> removedFilesToUnload = new ObjectArrayList<Path>();
            ObjectArrayList<Path> createdOrModifiedDirectories = new ObjectArrayList<Path>();
            ObjectArrayList<Path> removedFilesAndDirectories = new ObjectArrayList<Path>();
            block12: for (Map.Entry<Path, EventKind> entry : map.entrySet()) {
                Path path = entry.getKey();
                EventKind eventKind = entry.getValue();
                switch (eventKind) {
                    case ENTRY_CREATE: {
                        if (Files.isDirectory(path, new LinkOption[0])) {
                            CommonAssetModule.this.getLogger().at(Level.INFO).log("Directory Created: %s", path);
                            try {
                                Stream<Path> stream = Files.walk(path, FileUtil.DEFAULT_WALK_TREE_OPTIONS_ARRAY);
                                try {
                                    stream.forEach(child -> {
                                        BasicFileAttributes attributes;
                                        try {
                                            attributes = Files.readAttributes(child, BasicFileAttributes.class, new LinkOption[0]);
                                        }
                                        catch (IOException ignored) {
                                            return;
                                        }
                                        if (attributes.isDirectory()) {
                                            createdOrModifiedDirectories.add(path);
                                        } else if (attributes.isRegularFile()) {
                                            createdOrModifiedFilesToLoad.add(child);
                                        }
                                    });
                                    continue block12;
                                }
                                finally {
                                    if (stream == null) continue block12;
                                    stream.close();
                                    continue block12;
                                }
                            }
                            catch (IOException e) {
                                ((HytaleLogger.Api)CommonAssetModule.this.getLogger().at(Level.SEVERE).withCause(e)).log("Failed to reload assets in directory: %s", path);
                                break;
                            }
                        }
                        CommonAssetModule.this.getLogger().at(Level.INFO).log("File Created: %s", path);
                        createdOrModifiedFilesToLoad.add(path);
                        break;
                    }
                    case ENTRY_DELETE: {
                        CommonAssetModule.this.getLogger().at(Level.INFO).log("Deleted: %s", path);
                        removedFilesAndDirectories.add(path);
                        Path relative = PathUtil.relativize(this.commonPath, path);
                        String name2 = PatternUtil.replaceBackslashWithForwardSlash(relative.toString());
                        List<CommonAsset> commonAssets = CommonAssetRegistry.getCommonAssetsStartingWith(this.pack.getName(), name2);
                        for (CommonAsset asset : commonAssets) {
                            removedFilesToUnload.add(this.commonPath.resolve(asset.getName()));
                        }
                        continue block12;
                    }
                    case ENTRY_MODIFY: {
                        if (Files.isDirectory(path, new LinkOption[0])) {
                            CommonAssetModule.this.getLogger().at(Level.INFO).log("Directory Modified: %s", path);
                            createdOrModifiedDirectories.add(path);
                            break;
                        }
                        CommonAssetModule.this.getLogger().at(Level.INFO).log("File Modified: %s", path);
                        createdOrModifiedFilesToLoad.add(path);
                        break;
                    }
                    default: {
                        throw new IllegalArgumentException("Unknown eventKind " + String.valueOf((Object)eventKind));
                    }
                }
            }
            if (!(removedFilesAndDirectories.isEmpty() && createdOrModifiedFilesToLoad.isEmpty() && createdOrModifiedDirectories.isEmpty() || !(dispatchFor = HytaleServer.get().getEventBus().dispatchFor(CommonAssetMonitorEvent.class)).hasListener())) {
                dispatchFor.dispatch(new CommonAssetMonitorEvent(this.pack.getName(), createdOrModifiedFilesToLoad, removedFilesToUnload, createdOrModifiedDirectories, removedFilesAndDirectories));
            }
            ObjectArrayList<CompletableFuture<Void>> addedOrUpdatedAssets = new ObjectArrayList<CompletableFuture<Void>>();
            ObjectArrayList<CommonAssetRegistry.PackAsset> removedAssets = new ObjectArrayList<CommonAssetRegistry.PackAsset>();
            ObjectArrayList<CommonAsset> updatedAssets = new ObjectArrayList<CommonAsset>();
            if (!removedFilesToUnload.isEmpty()) {
                CommonAssetModule.this.getLogger().at(Level.INFO).log("Removing deleted assets: %s", removedFilesToUnload);
                for (Path path : removedFilesToUnload) {
                    Path relativePath = PathUtil.relativize(this.commonPath, path);
                    name = PatternUtil.replaceBackslashWithForwardSlash(relativePath.toString());
                    BooleanObjectPair<CommonAssetRegistry.PackAsset> removed = CommonAssetRegistry.removeCommonAssetByName(this.pack.getName(), name);
                    if (removed != null) {
                        if (removed.firstBoolean()) {
                            updatedAssets.add(((CommonAssetRegistry.PackAsset)removed.second()).asset());
                        } else {
                            removedAssets.add((CommonAssetRegistry.PackAsset)removed.second());
                        }
                    }
                    CommonAssetModule.this.assets.invalidate();
                }
                CommonAssetModule.this.sendRemoveAssets(removedAssets, false);
                CommonAssetModule.this.sendAssets(updatedAssets, false);
            }
            if (!createdOrModifiedFilesToLoad.isEmpty()) {
                CommonAssetModule.this.getLogger().at(Level.INFO).log("Reloading assets: %s", createdOrModifiedFilesToLoad);
                for (Path path : createdOrModifiedFilesToLoad) {
                    Path relative = PathUtil.relativize(this.commonPath, path);
                    name = PatternUtil.replaceBackslashWithForwardSlash(relative.toString());
                    CommonAssetModule.this.reloadAsset(addedOrUpdatedAssets, this.pack.getName(), path, name);
                }
                CompletableFuture.allOf((CompletableFuture[])addedOrUpdatedAssets.toArray(CompletableFuture[]::new)).thenAccept(v -> Universe.get().broadcastPacketNoCache(new RequestCommonAssetsRebuild()));
            } else {
                Universe.get().broadcastPacketNoCache(new RequestCommonAssetsRebuild());
            }
        }
    }
}

