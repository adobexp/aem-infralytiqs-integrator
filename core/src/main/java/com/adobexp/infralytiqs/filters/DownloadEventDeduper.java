package com.adobexp.infralytiqs.filters;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Suppresses duplicate {@code asset_download} events for the same user and normalized asset path
 * within a short window. Cart and bulk downloads trigger multiple HTTP handlers for one logical
 * download (e.g. {@code POST *.downloadbinaries.json} followed by {@code GET *.download.bin}).
 */
final class DownloadEventDeduper {

    /** Covers a full cart/bulk download flow without blocking intentional re-downloads for long. */
    static final long DEDUP_WINDOW_MS = 90_000L;

    private static final int MAX_ENTRIES = 10_000;

    private final ConcurrentHashMap<String, Long> recentByKey = new ConcurrentHashMap<>();

    /**
     * @return {@code true} when an equivalent event was already recorded within the dedup window
     */
    boolean isDuplicate(String userKey, String normalizedDownloadPath) {
        if (normalizedDownloadPath == null || normalizedDownloadPath.isEmpty()) {
            return false;
        }
        String key = dedupKey(userKey, normalizedDownloadPath);
        long now = System.currentTimeMillis();
        Long previous = recentByKey.get(key);
        if (previous != null && (now - previous) < DEDUP_WINDOW_MS) {
            return true;
        }
        recentByKey.put(key, now);
        evictExpired(now);
        return false;
    }

    static String dedupKey(String userKey, String normalizedDownloadPath) {
        String user = userKey == null || userKey.isBlank() ? "anonymous" : userKey;
        return user + '|' + normalizedDownloadPath;
    }

    private void evictExpired(long now) {
        if (recentByKey.size() <= MAX_ENTRIES) {
            return;
        }
        long cutoff = now - DEDUP_WINDOW_MS;
        for (Iterator<Map.Entry<String, Long>> it = recentByKey.entrySet().iterator(); it.hasNext();) {
            if (recentByKey.size() <= MAX_ENTRIES) {
                break;
            }
            Map.Entry<String, Long> entry = it.next();
            if (entry.getValue() < cutoff) {
                it.remove();
            }
        }
    }
}
