/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.monitor;

import com.hypixel.hytale.server.core.asset.monitor.EventKind;
import javax.annotation.Nonnull;

public class PathEvent {
    private final EventKind eventKind;
    private final long timestamp;

    public PathEvent(EventKind eventKind, long timestamp) {
        this.eventKind = eventKind;
        this.timestamp = timestamp;
    }

    public EventKind getEventKind() {
        return this.eventKind;
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    @Nonnull
    public String toString() {
        return "PathEvent{eventKind=" + String.valueOf((Object)this.eventKind) + ", timestamp=" + this.timestamp + "}";
    }
}

