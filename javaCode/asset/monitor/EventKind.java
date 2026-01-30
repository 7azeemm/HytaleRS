/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.monitor;

import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import javax.annotation.Nonnull;

public enum EventKind {
    ENTRY_CREATE,
    ENTRY_DELETE,
    ENTRY_MODIFY;


    @Nonnull
    public static EventKind parse(WatchEvent.Kind<Path> kind) {
        if (kind == StandardWatchEventKinds.ENTRY_CREATE) {
            return ENTRY_CREATE;
        }
        if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
            return ENTRY_DELETE;
        }
        if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
            return ENTRY_MODIFY;
        }
        throw new IllegalStateException("Unknown type: " + String.valueOf(kind));
    }
}

