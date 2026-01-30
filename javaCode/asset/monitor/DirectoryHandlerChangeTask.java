/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.monitor;

import com.hypixel.hytale.logger.HytaleLogger;
import com.hypixel.hytale.server.core.asset.monitor.AssetMonitor;
import com.hypixel.hytale.server.core.asset.monitor.AssetMonitorHandler;
import com.hypixel.hytale.server.core.asset.monitor.EventKind;
import com.hypixel.hytale.server.core.asset.monitor.PathEvent;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import it.unimi.dsi.fastutil.objects.ObjectArrayList;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import javax.annotation.Nonnull;

public class DirectoryHandlerChangeTask
implements Runnable {
    public static final HytaleLogger LOGGER = HytaleLogger.forEnclosingClass();
    private static final long ACCUMULATION_DELAY_MILLIS = 1000L;
    private final AssetMonitor assetMonitor;
    private final Path parent;
    private final AssetMonitorHandler handler;
    @Nonnull
    private final ScheduledFuture<?> task;
    private final AtomicBoolean changed = new AtomicBoolean(true);
    private final Map<Path, PathEvent> paths = new Object2ObjectOpenHashMap<Path, PathEvent>();

    public DirectoryHandlerChangeTask(AssetMonitor assetMonitor, Path parent, AssetMonitorHandler handler) {
        this.assetMonitor = assetMonitor;
        this.parent = parent;
        this.handler = handler;
        this.task = AssetMonitor.runTask(this, 1000L);
    }

    @Override
    public void run() {
        if (!this.changed.getAndSet(false)) {
            this.cancelSchedule();
            try {
                LOGGER.at(Level.FINER).log("run: %s", this.paths);
                ObjectArrayList<Map.Entry> entries = new ObjectArrayList<Map.Entry>(this.paths.size());
                for (Map.Entry<Path, PathEvent> entry : this.paths.entrySet()) {
                    entries.add(new AbstractMap.SimpleEntry<Path, PathEvent>(entry.getKey(), entry.getValue()));
                }
                this.paths.clear();
                entries.sort(Comparator.comparingLong(value -> ((PathEvent)value.getValue()).getTimestamp()));
                HashSet<String> fileNames = new HashSet<String>();
                Object2ObjectOpenHashMap<Path, EventKind> eventPaths = new Object2ObjectOpenHashMap<Path, EventKind>();
                for (Map.Entry entry : entries) {
                    if (!fileNames.add(((Path)entry.getKey()).getFileName().toString())) {
                        LOGGER.at(Level.FINER).log("run handler.accept(%s)", eventPaths);
                        this.handler.accept(eventPaths);
                        eventPaths = new Object2ObjectOpenHashMap();
                        fileNames.clear();
                    }
                    eventPaths.put((Path)entry.getKey(), ((PathEvent)entry.getValue()).getEventKind());
                }
                if (!eventPaths.isEmpty()) {
                    LOGGER.at(Level.FINER).log("run handler.accept(%s)", eventPaths);
                    this.handler.accept(eventPaths);
                }
            }
            catch (Exception e) {
                ((HytaleLogger.Api)LOGGER.at(Level.SEVERE).withCause(e)).log("Failed to run: %s", this);
            }
        }
    }

    public AssetMonitor getAssetMonitor() {
        return this.assetMonitor;
    }

    public Path getParent() {
        return this.parent;
    }

    public AssetMonitorHandler getHandler() {
        return this.handler;
    }

    public void addPath(Path path, PathEvent pathEvent) {
        LOGGER.at(Level.FINEST).log("addPath(%s, %s): %s", path, pathEvent, this);
        this.paths.put(path, pathEvent);
        this.changed.set(true);
    }

    public void removePath(Path path) {
        LOGGER.at(Level.FINEST).log("removePath(%s, %s): %s", (Object)path, (Object)this);
        this.paths.remove(path);
        if (this.paths.isEmpty()) {
            this.cancelSchedule();
        } else {
            this.changed.set(true);
        }
    }

    public void markChanged() {
        AssetMonitor.LOGGER.at(Level.FINEST).log("markChanged(): %s", this);
        this.changed.set(true);
    }

    public void cancelSchedule() {
        LOGGER.at(Level.FINEST).log("cancelSchedule(): %s", this);
        this.assetMonitor.removeHookChangeTask(this);
        if (this.task != null && !this.task.isDone()) {
            this.task.cancel(false);
        }
    }

    @Nonnull
    public String toString() {
        return "DirectoryHandlerChangeTask{parent=" + String.valueOf(this.parent) + ", handler=" + String.valueOf(this.handler) + ", changed=" + String.valueOf(this.changed) + ", paths=" + String.valueOf(this.paths) + "}";
    }
}

