/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.monitor;

import com.hypixel.hytale.logger.HytaleLogger;
import com.hypixel.hytale.logger.sentry.SkipSentryException;
import com.hypixel.hytale.server.core.asset.monitor.AssetMonitorHandler;
import com.hypixel.hytale.server.core.asset.monitor.DirectoryHandlerChangeTask;
import com.hypixel.hytale.server.core.asset.monitor.EventKind;
import com.hypixel.hytale.server.core.asset.monitor.FileChangeTask;
import com.hypixel.hytale.server.core.asset.monitor.PathEvent;
import com.hypixel.hytale.server.core.asset.monitor.PathWatcherThread;
import com.hypixel.hytale.server.core.util.concurrent.ThreadUtil;
import com.hypixel.hytale.sneakythrow.SneakyThrow;
import it.unimi.dsi.fastutil.objects.ObjectArrayList;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import javax.annotation.Nonnull;

public class AssetMonitor {
    public static final HytaleLogger LOGGER = HytaleLogger.forEnclosingClass();
    private static final ScheduledExecutorService EXECUTOR = Executors.newSingleThreadScheduledExecutor(ThreadUtil.daemon("AssetMonitor Thread"));
    private final Map<Path, List<AssetMonitorHandler>> directoryMonitors = new ConcurrentHashMap<Path, List<AssetMonitorHandler>>();
    private final Map<Path, FileChangeTask> fileChangeTasks = new ConcurrentHashMap<Path, FileChangeTask>();
    private final Map<Path, Map<AssetMonitorHandler, DirectoryHandlerChangeTask>> directoryHandlerChangeTasks = new ConcurrentHashMap<Path, Map<AssetMonitorHandler, DirectoryHandlerChangeTask>>();
    @Nonnull
    private final PathWatcherThread pathWatcherThread = new PathWatcherThread(this::onChange);

    public AssetMonitor() throws IOException {
        this.pathWatcherThread.start();
    }

    public void shutdown() {
        this.pathWatcherThread.shutdown();
    }

    public void monitorDirectoryFiles(@Nonnull Path path, @Nonnull AssetMonitorHandler handler) {
        if (!Files.isDirectory(path, new LinkOption[0])) {
            throw new IllegalArgumentException(String.valueOf(path));
        }
        try {
            Path normalize = path.toAbsolutePath().normalize();
            LOGGER.at(Level.FINE).log("Monitoring Directory: %s", normalize);
            ((List)this.directoryMonitors.computeIfAbsent(normalize, SneakyThrow.sneakyFunction(k -> {
                this.pathWatcherThread.addPath((Path)k);
                return new ObjectArrayList();
            }))).add(handler);
        }
        catch (Exception e) {
            ((HytaleLogger.Api)LOGGER.at(Level.SEVERE).withCause(new SkipSentryException(e))).log("Failed to monitor directory: %s", path);
        }
    }

    public void removeMonitorDirectoryFiles(@Nonnull Path path, @Nonnull Object key) {
        if (!Files.isDirectory(path, new LinkOption[0])) {
            throw new IllegalArgumentException(String.valueOf(path));
        }
        try {
            Path normalize = path.toAbsolutePath().normalize();
            LOGGER.at(Level.FINE).log("Monitoring Directory: %s", normalize);
            ((List)this.directoryMonitors.computeIfAbsent(normalize, SneakyThrow.sneakyFunction(k -> {
                this.pathWatcherThread.addPath((Path)k);
                return new ObjectArrayList();
            }))).removeIf(v -> v.getKey().equals(key));
        }
        catch (Exception e) {
            ((HytaleLogger.Api)LOGGER.at(Level.SEVERE).withCause(new SkipSentryException(e))).log("Failed to monitor directory: %s", path);
        }
    }

    protected void onChange(@Nonnull Path file, EventKind eventKind) {
        boolean createdOrModified;
        LOGGER.at(Level.FINER).log("onChange: %s of %s", (Object)file, (Object)eventKind);
        Path path = file.toAbsolutePath().normalize();
        FileChangeTask oldTask = this.fileChangeTasks.remove(path);
        if (oldTask != null) {
            oldTask.cancelSchedule();
        }
        for (Map<AssetMonitorHandler, DirectoryHandlerChangeTask> tasks : this.directoryHandlerChangeTasks.values()) {
            for (DirectoryHandlerChangeTask task : tasks.values()) {
                task.removePath(path);
            }
        }
        boolean bl = createdOrModified = eventKind == EventKind.ENTRY_CREATE || eventKind == EventKind.ENTRY_MODIFY;
        if (createdOrModified && !Files.exists(path, new LinkOption[0])) {
            LOGGER.at(Level.WARNING).log("The asset file '%s' was deleted before we could load/update it!", path);
            return;
        }
        try {
            this.fileChangeTasks.put(path, new FileChangeTask(this, path, new PathEvent(eventKind, System.nanoTime())));
        }
        catch (FileNotFoundException | AccessDeniedException | NoSuchFileException e) {
            LOGGER.at(Level.WARNING).log("The asset file '%s' was deleted before we could load/update it!", path);
        }
        catch (IOException e) {
            ((HytaleLogger.Api)LOGGER.at(Level.SEVERE).withCause(e)).log("Failed to queue asset to be reloaded %s", path);
        }
    }

    public void onDelayedChange(@Nonnull Path path, @Nonnull PathEvent pathEvent) {
        LOGGER.at(Level.FINER).log("onDelayedChange: %s of %s", (Object)path, (Object)pathEvent);
        for (Map.Entry<Path, List<AssetMonitorHandler>> entry : this.directoryMonitors.entrySet()) {
            Path parent = entry.getKey();
            if (!path.startsWith(parent)) continue;
            Map tasks = this.directoryHandlerChangeTasks.computeIfAbsent(parent, k -> new ConcurrentHashMap());
            for (AssetMonitorHandler directoryHandler : entry.getValue()) {
                try {
                    if (!directoryHandler.test(path, pathEvent.getEventKind())) continue;
                    tasks.computeIfAbsent(directoryHandler, handler -> new DirectoryHandlerChangeTask(this, parent, (AssetMonitorHandler)handler)).addPath(path, pathEvent);
                }
                catch (Exception e) {
                    ((HytaleLogger.Api)LOGGER.at(Level.SEVERE).withCause(e)).log("Failed to run directoryHandler.test for parent: %s, %s of %s", parent, path, pathEvent);
                }
            }
        }
    }

    public void removeFileChangeTask(@Nonnull FileChangeTask fileChangeTask) {
        this.fileChangeTasks.remove(fileChangeTask.getPath());
    }

    public void markChanged(@Nonnull Path path) {
        for (Map.Entry<Path, Map<AssetMonitorHandler, DirectoryHandlerChangeTask>> entry : this.directoryHandlerChangeTasks.entrySet()) {
            Path parent = entry.getKey();
            if (!path.startsWith(parent)) continue;
            for (DirectoryHandlerChangeTask hookChangeTask : entry.getValue().values()) {
                hookChangeTask.markChanged();
            }
        }
    }

    public void removeHookChangeTask(@Nonnull DirectoryHandlerChangeTask directoryHandlerChangeTask) {
        AssetMonitorHandler hook = directoryHandlerChangeTask.getHandler();
        this.directoryHandlerChangeTasks.compute(directoryHandlerChangeTask.getParent(), (k, map) -> {
            if (map == null) {
                return null;
            }
            map.remove(hook);
            return map.isEmpty() ? null : map;
        });
    }

    @Nonnull
    public static ScheduledFuture<?> runTask(@Nonnull Runnable task, long millisDelay) {
        return EXECUTOR.scheduleWithFixedDelay(task, millisDelay, millisDelay, TimeUnit.MILLISECONDS);
    }
}

