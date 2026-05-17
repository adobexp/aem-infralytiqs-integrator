package com.adobexp.infralytiqs.service;

/**
 * Queue-side API for AEM-side analytics ingestion into Infralytiqs (ClickHouse via st-ck-server).
 *
 * <p>The implementation collects events, batches them, and POSTs JSON to
 * {@code POST {baseUri}/il/analytics/{tenantId}/{siteId}/events}.
 */
public interface InfralytiqsService {

    /**
     * Enqueues one analytics event for batched ingestion. Calls are lightweight and should not block.
     * If internal queue caps are exceeded, newer events may be dropped (see OSGi diagnostics logging).
     */
    void enqueue(InfralytiqsAnalyticsPayload event);

    /**
     * Requests an asynchronous flush of the current batch backlog (mostly for tests / shutdown hooks).
     */
    void requestFlushAsync();

    /**
     * Best-effort current size of the in-memory backlog waiting for batched HTTP flush. Bulk
     * producers (e.g. the DAM disk-usage scheduler emitting tens of thousands of folder rows
     * per run) call this to self-pace and avoid silently overflowing the queue.
     *
     * <p>Default returns {@code -1} meaning "introspection not supported" — callers must treat
     * a negative return as "skip pacing". This keeps the interface forward-compatible for any
     * future implementation that doesn't expose its backlog.
     */
    default int approximateBacklogSize() {
        return -1;
    }

    /**
     * Best-effort total capacity of the in-memory backlog. Combined with
     * {@link #approximateBacklogSize()} to compute fill ratio. Default {@code -1} =
     * "introspection not supported".
     */
    default int approximateBacklogCapacity() {
        return -1;
    }
}
