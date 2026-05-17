package com.adobexp.infralytiqs.listeners;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;
import com.day.cq.replication.ReplicationAction;
import com.day.cq.replication.ReplicationActionType;
import com.day.cq.replication.ReplicationEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.event.Event;
import org.osgi.service.event.EventConstants;
import org.osgi.service.event.EventHandler;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

/**
 * Captures AEM asset publish (activate) and unpublish (deactivate) events and ships one
 * Infralytiqs analytics row per asset path so the resulting ClickHouse rows directly support
 * the two reporting questions the product needs:
 *
 * <ol>
 *   <li><b>"What assets did user X publish?"</b> — single {@code GROUP BY user_id_hint, asset_path}
 *       on rows where {@code event_type = 'asset_publish'}.</li>
 *   <li><b>"What assets were published in this time window?"</b> — single
 *       {@code WHERE event_timestamp BETWEEN ?? AND ??} on the same rows. The ingest server
 *       stamps {@code event_timestamp} on receipt; for sub-second accuracy we also carry the
 *       replication-action time as the {@code publish_event_time_iso} dimension and the
 *       millisecond {@code publish_event_time_ms} metric.</li>
 * </ol>
 *
 * <h2>Event shape — why one row per asset, not one row per replication</h2>
 *
 * <p>A single replication action can carry many paths ({@link ReplicationAction#getPaths()} is an
 * array). Storing one row per replication with a CSV {@code paths} dimension would force every
 * downstream reporting query to {@code arrayJoin} (ClickHouse) / unnest (Postgres) and would make
 * "give me the assets user X published" prohibitively expensive over millions of rows. We
 * therefore explode the array on the AEM side and emit one row per {@code (replication-action,
 * asset-path)} tuple. The {@code replication_batch_id} dimension is shared by every row of the
 * same replication so the original grouping is recoverable when needed.
 *
 * <h2>Configuration policy + runmode placement</h2>
 *
 * <p>The component is declared {@link ConfigurationPolicy#REQUIRE}, so Declarative Services does
 * not register this {@link EventHandler} (and the filter does not subscribe to the
 * {@link ReplicationEvent#EVENT_TOPIC} topic) until Configuration Admin sees a matching PID.
 * Operators control rollout by deploying — or not deploying — the
 * {@code com.adobexp.infralytiqs.listeners.AssetPublishEventListener.cfg.json} file.
 *
 * <p>The deployment cfg.json lives under {@code .../osgiconfig/config.author/} on purpose.
 * {@link ReplicationEvent} fires on BOTH author (when a user initiates a replication via
 * {@code /bin/replicate}) and on each publish instance (when the publish receives the
 * replicated payload). The same activation would therefore be recorded twice — once on each
 * tier — if the config were installed in plain {@code config/}. By binding to the
 * {@code author} runmode we capture exactly the user-initiated event with the genuine
 * {@link ReplicationAction#getUserId()}, which is the row we want for "who published what".
 *
 * <h2>Path whitelist semantics</h2>
 *
 * <p>{@link AssetPublishCfg#whitelistedPaths()} accepts a list of JCR path prefixes. A path is
 * recorded iff {@code assetPath.equals(prefix)} OR {@code assetPath.startsWith(prefix + "/")} for
 * at least one entry. This is intentionally prefix-only (not glob / regex) so the matcher is a
 * single {@code startsWith} call per (path, prefix) pair — constant time per replication.
 *
 * <p>The default is {@code "/content/dam"} which covers all DAM assets. Operators can narrow to
 * a specific tenant subtree (e.g. {@code /content/dam/testdownload}) to limit ingestion volume.
 *
 * <h2>What we deliberately do NOT do</h2>
 *
 * <ul>
 *   <li>No {@code ResourceResolver} acquisition — every datum we emit is already on the
 *       {@link ReplicationAction} object. Avoiding a system-user login keeps the listener
 *       zero-config from a JCR-permissions standpoint and removes one entire failure mode.</li>
 *   <li>No async/queue inside the handler. {@link InfralytiqsService#enqueue} is itself a
 *       non-blocking append to a bounded in-memory queue (see {@code InfralytiqsServiceImpl});
 *       the OSGi event dispatcher thread returns within microseconds.</li>
 *   <li>No filtering by {@code dam:Asset} resource type. We trust the path-prefix whitelist
 *       (rooted at {@code /content/dam}) instead of taking another JCR read just to verify the
 *       node type — the prefix is sufficient guard against replications of e.g.
 *       {@code /content/sites/*} ending up here.</li>
 * </ul>
 */
@Component(
        service = EventHandler.class,
        immediate = false,
        configurationPid = AssetPublishEventListener.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {
                Constants.SERVICE_DESCRIPTION + "=Infralytiqs | Asset Publish Event Listener",
                EventConstants.EVENT_TOPIC + "=" + ReplicationEvent.EVENT_TOPIC
        })
@Designate(ocd = AssetPublishEventListener.AssetPublishCfg.class)
public final class AssetPublishEventListener implements EventHandler {

    static final String PID = "com.adobexp.infralytiqs.listeners.AssetPublishEventListener";

    private static final Logger LOG = LoggerFactory.getLogger(AssetPublishEventListener.class);

    @ObjectClassDefinition(
            name = "Infralytiqs Asset Publish Event Listener",
            description = "Subscribes to com/day/cq/replication events and ships one Infralytiqs "
                    + "analytics row per asset path per replication action. Deploy the OSGi config "
                    + "under /apps/.../osgiconfig/config.author/ so it only runs on AEMaaCS author "
                    + "(replication events also fire on publish on receipt, which would double-count).")
    public @interface AssetPublishCfg {

        @AttributeDefinition(
                name = "Comment",
                description = "Optional textual hint for admins — unused at runtime.")
        String marker() default "";

        @AttributeDefinition(
                name = "Whitelisted DAM path prefixes",
                description = "Asset paths are recorded iff they equal one of these prefixes or "
                        + "start with one of these prefixes followed by '/'. Default is "
                        + "'/content/dam' which covers every DAM asset. Narrow to e.g. "
                        + "'/content/dam/testdownload' to limit recording to a single tenant.")
        String[] whitelistedPaths() default {"/content/dam"};

        @AttributeDefinition(
                name = "Track ACTIVATE (publish)",
                description = "When true (default), records a row with subtype "
                        + "'asset_publish_status_success' for each asset path in an ACTIVATE.")
        boolean trackActivate() default true;

        @AttributeDefinition(
                name = "Track DEACTIVATE (unpublish)",
                description = "When true (default), records a row with subtype "
                        + "'asset_unpublish_status_success' for each asset path in a DEACTIVATE. "
                        + "Disable if you only want publish events in the report.")
        boolean trackDeactivate() default true;

        @AttributeDefinition(
                name = "Max paths recorded per single replication",
                description = "Hard cap on how many asset paths from one ReplicationAction get "
                        + "exploded into individual events. Protects the ingest queue from a "
                        + "tree-publish that targets thousands of assets in one go. Default 1000 "
                        + "matches the ingest service's per-batch ceiling.")
        int maxPathsPerReplication() default 1000;
    }

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile InfralytiqsService ingestPipeline;

    private volatile List<String> whitelistedPaths = Collections.emptyList();
    private volatile boolean trackActivate = true;
    private volatile boolean trackDeactivate = true;
    private volatile int maxPathsPerReplication = 1000;

    @Activate
    @Modified
    void activate(AssetPublishCfg cfg) {
        List<String> normalized = new ArrayList<>();
        for (String raw : cfg.whitelistedPaths()) {
            if (raw == null) {
                continue;
            }
            String trimmed = raw.trim();
            if (trimmed.isEmpty() || !trimmed.startsWith("/")) {
                LOG.warn("[{}] ignoring whitelist entry '{}' — must start with '/'", PID, raw);
                continue;
            }
            // Strip trailing slash(es) so '/content/dam/' and '/content/dam' behave identically.
            // The prefix match below appends '/' explicitly when checking descendants.
            while (trimmed.length() > 1 && trimmed.endsWith("/")) {
                trimmed = trimmed.substring(0, trimmed.length() - 1);
            }
            normalized.add(trimmed);
        }

        this.whitelistedPaths = Collections.unmodifiableList(normalized);
        this.trackActivate = cfg.trackActivate();
        this.trackDeactivate = cfg.trackDeactivate();
        this.maxPathsPerReplication = Math.max(1, cfg.maxPathsPerReplication());

        if (whitelistedPaths.isEmpty()) {
            LOG.warn("[{}] no whitelisted paths configured — listener will record nothing", PID);
        } else {
            LOG.info(
                    "[{}] activated; whitelistedPaths={}, trackActivate={}, trackDeactivate={}, maxPathsPerReplication={}",
                    PID, whitelistedPaths, trackActivate, trackDeactivate, maxPathsPerReplication);
        }
    }

    @Override
    public void handleEvent(Event osgiEvent) {
        // ReplicationEvent.fromEvent unpacks the OSGi event into a typed wrapper. Returns null
        // for events on the topic that are not actually replication events (unlikely on the
        // dedicated com/day/cq/replication topic but defensive).
        ReplicationEvent replicationEvent;
        try {
            replicationEvent = ReplicationEvent.fromEvent(osgiEvent);
        } catch (Exception ex) {
            LOG.debug("[{}] not a ReplicationEvent (topic={}): {}", PID, osgiEvent.getTopic(), ex.toString());
            return;
        }
        if (replicationEvent == null) {
            return;
        }

        ReplicationAction action = replicationEvent.getReplicationAction();
        if (action == null) {
            return;
        }

        ReplicationActionType type = action.getType();
        if (type == null) {
            return;
        }

        boolean isActivate = type == ReplicationActionType.ACTIVATE;
        boolean isDeactivate = type == ReplicationActionType.DEACTIVATE;
        if (!isActivate && !isDeactivate) {
            // We deliberately ignore TEST, DELETE, INTERNAL_POLL, etc. — those are not user-facing
            // "publish/unpublish" actions and would pollute the report.
            return;
        }
        if (isActivate && !trackActivate) {
            return;
        }
        if (isDeactivate && !trackDeactivate) {
            return;
        }

        String[] rawPaths = action.getPaths();
        if (rawPaths == null || rawPaths.length == 0) {
            return;
        }

        InfralytiqsService ingest = ingestPipeline;
        if (ingest == null) {
            LOG.warn("[{}] {} replication for {} path(s) ignored — ingest pipeline not bound",
                    PID, type.getName(), rawPaths.length);
            return;
        }

        String userId = action.getUserId();
        long timeMs = action.getTime();
        // Some replication agents leave time=0 when the action object is freshly synthesised
        // (e.g. dispatcher polls) — substitute the wall clock so the dimension stays parseable.
        if (timeMs <= 0L) {
            timeMs = System.currentTimeMillis();
        }
        String timeIso = Instant.ofEpochMilli(timeMs).toString();
        // Stable correlation id for every row that came out of this single replication, so the
        // original "user published these N assets together" grouping is recoverable from the
        // exploded rows. Lower-cased hex hash of (user|time|first-path) — sufficient for
        // correlation without depending on the action object surviving past handleEvent.
        String batchId = correlationId(userId, timeMs, rawPaths[0]);

        int emitted = 0;
        int filtered = 0;
        for (String path : rawPaths) {
            if (emitted >= maxPathsPerReplication) {
                LOG.warn("[{}] replication {} truncated at {} of {} paths (maxPathsPerReplication cap)",
                        PID, batchId, emitted, rawPaths.length);
                break;
            }
            if (path == null || path.isEmpty()) {
                continue;
            }
            if (!matchesWhitelist(path, whitelistedPaths)) {
                filtered++;
                continue;
            }

            String parent = parentOf(path);
            String name = nameOf(path);
            String ext = extensionOf(name);
            // tenant_subtree is the first 4 segments below /content/dam — used as a low-cardinality
            // grouping dimension (e.g. '/content/dam/testdownload') for tenant-level dashboards.
            String tenantSubtree = tenantSubtreeOf(path);

            InfralytiqsAnalyticsPayload.Builder b =
                    InfralytiqsAnalyticsPayload.builder("asset_publish")
                            .eventSubtype(isActivate
                                    ? "asset_publish_status_success"
                                    : "asset_unpublish_status_success")
                            // lookupPath drives tenant routing in InfralytiqsServiceImpl
                            // (TenantServiceManager.getConfigForPath). Using asset_path here means
                            // each row is routed to whichever tenant owns the asset's subtree.
                            .lookupPath(path)
                            .pageUrl(path)
                            .userIdHint(userId)
                            .dimension("asset_path", trim(path, 2048))
                            .dimension("asset_name", trim(name, 512))
                            .dimension("asset_parent_path", trim(parent, 2048))
                            .dimension("asset_extension", trim(ext, 64))
                            .dimension("asset_tenant_subtree", trim(tenantSubtree, 1024))
                            .dimension("replication_action", type.getName())
                            .dimension("replication_batch_id", batchId)
                            .dimension("publish_event_time_iso", timeIso)
                            .metric("publish_event_time_ms", (double) timeMs)
                            .metric("asset_publish_count", isActivate ? 1.0 : 0.0)
                            .metric("asset_unpublish_count", isDeactivate ? 1.0 : 0.0);

            ingest.enqueue(b.build());
            emitted++;
        }

        if (emitted > 0) {
            LOG.info("[{}] dispatched {} {} event(s) (filtered {}, batchId={}, user={})",
                    PID, emitted, type.getName(), filtered, batchId, userId);
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("[{}] {} replication for {} path(s) had no whitelist match (batchId={}, user={})",
                    PID, type.getName(), rawPaths.length, batchId, userId);
        }
    }

    /**
     * True iff {@code path} equals one of the whitelist entries or is a descendant
     * ({@code prefix + "/"}-rooted) of one. The {@code + "/"} guard prevents
     * {@code "/content/damaged"} matching a {@code "/content/dam"} prefix.
     */
    static boolean matchesWhitelist(String path, List<String> whitelist) {
        for (String prefix : whitelist) {
            if (path.equals(prefix)) {
                return true;
            }
            if (path.startsWith(prefix) && path.length() > prefix.length()
                    && path.charAt(prefix.length()) == '/') {
                return true;
            }
        }
        return false;
    }

    /**
     * Stable, short correlation id shared by every row exploded out of the same replication.
     * Not a security primitive — just a join key. SHA-256 truncated to 16 hex chars (64 bits) is
     * more than enough for join uniqueness across a single tenant's daily volume.
     */
    static String correlationId(String userId, long timeMs, String firstPath) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(Objects.toString(userId, "").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update((byte) '|');
            md.update(Long.toString(timeMs).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update((byte) '|');
            md.update(Objects.toString(firstPath, "").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] digest = md.digest();
            StringBuilder hex = new StringBuilder(16);
            for (int i = 0; i < 8; i++) {
                hex.append(String.format(Locale.ROOT, "%02x", digest[i]));
            }
            return hex.toString();
        } catch (java.security.NoSuchAlgorithmException ex) {
            // SHA-256 is required by the JRE spec — never reached.
            return Long.toHexString(timeMs);
        }
    }

    private static String parentOf(String path) {
        int idx = path.lastIndexOf('/');
        return idx <= 0 ? "/" : path.substring(0, idx);
    }

    private static String nameOf(String path) {
        int idx = path.lastIndexOf('/');
        return idx < 0 ? path : path.substring(idx + 1);
    }

    private static String extensionOf(String name) {
        int dot = name.lastIndexOf('.');
        if (dot <= 0 || dot == name.length() - 1) {
            return "";
        }
        return name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    /**
     * Returns the first four segments of {@code path} when rooted at {@code /content/dam}, e.g.
     * {@code /content/dam/testdownload/foo/bar.jpg → /content/dam/testdownload}. Used as a
     * low-cardinality grouping dimension. Returns the parent of the asset for non-DAM paths so
     * the dimension is never empty.
     */
    static String tenantSubtreeOf(String path) {
        if (path == null || !path.startsWith("/content/dam/")) {
            return parentOf(Objects.toString(path, ""));
        }
        int from = "/content/dam/".length();
        int slash = path.indexOf('/', from);
        if (slash < 0) {
            return path;
        }
        return path.substring(0, slash);
    }

    private static String trim(String candidate, int max) {
        if (candidate == null) {
            return "";
        }
        return candidate.length() <= max ? candidate : candidate.substring(0, max);
    }

    /**
     * Convenience for tests — re-exposes the configured whitelist for assertion in unit tests
     * without making the field non-private. Safe to call from any thread (snapshot of a
     * volatile read).
     */
    List<String> currentWhitelistedPaths() {
        return whitelistedPaths;
    }

    /** Convenience for tests. */
    static List<String> normalise(String... raw) {
        List<String> out = new ArrayList<>(raw.length);
        for (String r : raw) {
            if (r != null && r.startsWith("/")) {
                String t = r.trim();
                while (t.length() > 1 && t.endsWith("/")) {
                    t = t.substring(0, t.length() - 1);
                }
                out.add(t);
            }
        }
        return Collections.unmodifiableList(out);
    }

    /** Convenience for tests / Felix console — describes the active gate set for one event. */
    static String describeGates(boolean activate, boolean deactivate, int cap, List<String> wl) {
        return "trackActivate=" + activate + ",trackDeactivate=" + deactivate
                + ",cap=" + cap + ",whitelist=" + Arrays.toString(wl.toArray());
    }
}
