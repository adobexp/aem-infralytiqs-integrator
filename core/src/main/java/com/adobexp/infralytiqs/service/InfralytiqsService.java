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
}
