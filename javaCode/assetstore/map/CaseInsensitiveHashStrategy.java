/*
 * Decompiled with CFR 0.152.
 */
package com.hypixel.hytale.assetstore.map;

import it.unimi.dsi.fastutil.Hash;

public class CaseInsensitiveHashStrategy<K>
implements Hash.Strategy<K> {
    private static final CaseInsensitiveHashStrategy INSTANCE = new CaseInsensitiveHashStrategy();

    public static <K> CaseInsensitiveHashStrategy<K> getInstance() {
        return INSTANCE;
    }

    @Override
    public int hashCode(K key) {
        if (key == null) {
            return 0;
        }
        if (key instanceof String) {
            String s = (String)key;
            int hash = 0;
            for (int i = 0; i < s.length(); ++i) {
                hash = 31 * hash + Character.toLowerCase(s.charAt(i));
            }
            return hash;
        }
        return key.hashCode();
    }

    @Override
    public boolean equals(K a, K b) {
        if (a == b) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        if (a instanceof String) {
            String sa = (String)a;
            if (b instanceof String) {
                String sb = (String)b;
                return sa.equalsIgnoreCase(sb);
            }
        }
        return a.equals(b);
    }
}

