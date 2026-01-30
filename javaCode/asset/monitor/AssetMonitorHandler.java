/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.server.core.asset.monitor;

import com.hypixel.hytale.server.core.asset.monitor.EventKind;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Consumer;

public interface AssetMonitorHandler
extends BiPredicate<Path, EventKind>,
Consumer<Map<Path, EventKind>> {
    public Object getKey();
}

