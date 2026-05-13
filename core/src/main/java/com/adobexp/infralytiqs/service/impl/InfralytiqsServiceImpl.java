/*
 * Logging uses com.adobexp.log (via aem-loki-integrator.core) instead of org.slf4j imports.
 */
package com.adobexp.infralytiqs.service.impl;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.jcr.Node;
import javax.jcr.NodeIterator;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.Privilege;
import javax.net.ssl.SSLContext;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@Component(
        service = InfralytiqsService.class,
        immediate = true,
        configurationPid = InfralytiqsServiceImpl.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE)
@Designate(ocd = InfralytiqsServiceImpl.InfralytiqsServiceCfg.class)
public final class InfralytiqsServiceImpl implements InfralytiqsService {

    static final String PID = "com.adobexp.infralytiqs.service.impl.InfralytiqsServiceImpl";

    private static final Logger LOG = LoggerFactory.getLogger(InfralytiqsServiceImpl.class);

    /** Shared, thread-safe by design when only used for read operations (readTree). */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @ObjectClassDefinition(
            name = "Infralytiqs — analytics ingest configuration",
            description = "Registers the Infralytiqs ingestion service toward st-ck-server (ClickHouse ingest).")
    public @interface InfralytiqsServiceCfg {

        @AttributeDefinition(
                name = "API Server URI",
                description = "st-ck-server root, e.g. http://localhost:8080 — trailing slashes are tolerated.")
        String apiServerURI() default "http://localhost:8080";

        @AttributeDefinition(
                name = "Tenant Id",
                description = "ClickHouse tenantId registered in IL moduleConfigurations on st-ck-server.")
        String tenantId();

        @AttributeDefinition(
                name = "Site Id",
                description = "ClickHouse siteId registered alongside tenantId on st-ck-server.")
        String siteId();

        @AttributeDefinition(
                name = "ClickHouse DB Name",
                description = "Logical ClickHouse database receiving the analytics rows (e.g. PublicisDB).")
        String dbName();

        @AttributeDefinition(name = "Batch max events", description = "Events per POST (must be ≤ 1000 on server).") int batchMaxEvents() default 100;

        @AttributeDefinition(
                name = "Batch flush interval (ms)",
                description = "Fixed-rate timer that builds batches from the backlog even when traffic is bursty.")
        int flushIntervalMs() default 2500;

        @AttributeDefinition(
                name = "Queue capacity",
                description = "Upper bound for the in-memory backlog — when exhausted, enqueue is rejected.")
        int queueCapacity() default 50000;

        @AttributeDefinition(name = "HTTP timeout (seconds)", description = "Deadline for ingest HTTP exchanges.") int httpTimeoutSeconds()
                default 30;

        @AttributeDefinition(
                name = "Max concurrent posts",
                description = "Thread-pool size that performs outbound HTTP calls (each call carries up to batch max events).")
        int maxConcurrentPosts() default 2;

        @AttributeDefinition(
                name = "Enrich userId hints with profile (email + display name)",
                description =
                        "When true (default), each batched payload's userIdHint is asynchronously resolved into JCR profile fields on the worker thread before sending. Off the request thread.")
        boolean userEnrichmentEnabled() default true;

        @AttributeDefinition(
                name = "Enrichment sub-service name",
                description = "Sling sub-service mapped to a JCR system user with read access to /home/users.")
        String userEnrichmentSubService() default "user-enrichment";

        @AttributeDefinition(
                name = "User profile cache TTL (seconds)",
                description = "How long resolved profiles stay cached before being re-read from JCR.")
        int userCacheTtlSeconds() default 300;

        @AttributeDefinition(
                name = "User profile cache max entries",
                description = "Hard cap on the in-memory user-profile cache; oldest entries are evicted when exceeded.")
        int userCacheMaxEntries() default 5000;

        @AttributeDefinition(
                name = "Scan accessible DAM folders during enrichment",
                description = "When true, after resolving the user profile the worker thread also walks the direct children of "
                        + "'damVisibilityScanRoot' and computes which folders the user (or their groups) is allowed to read. "
                        + "The result is cached alongside the profile and emitted as 'accessible_dam_folders'.")
        boolean damVisibilityScanEnabled() default true;

        @AttributeDefinition(
                name = "DAM visibility scan root",
                description = "JCR path whose direct children are inspected for read access. Default '/content/dam'.")
        String damVisibilityScanRoot() default "/content/dam";

        @AttributeDefinition(
                name = "DAM visibility scan max folders",
                description = "Sanity cap on the number of accessible folders reported per user. Above this we stop scanning.")
        int damVisibilityScanMaxFolders() default 100;

        @AttributeDefinition(
                name = "Visibility probe paths (tagged)",
                description = "Tagged JCR-path probes evaluated once per uncached user, off the request thread. "
                        + "Each entry is a JSON object with three required fields: "
                        + "'eventName' (custom-dimension key the report engine filters on, e.g. 'DAM'), "
                        + "'eventValue' (token added to that dimension when the user can read 'path', e.g. 'ARC-DAM'), "
                        + "and 'path' (absolute JCR path to test). On a match, the resolved profile gets "
                        + "custom_dimensions[eventName] = JSON array of all matched eventValues for that name "
                        + "(insertion-ordered, deduped) — so multiple entries can share the same eventName to "
                        + "produce multi-value tags. Example entry (one String[] element): "
                        + "{\"eventName\":\"DAM\",\"eventValue\":\"ARC-DAM\",\"path\":\"/content/dam/px/arc\"}. "
                        + "Performance: O(N) extra ACL lookups per uncached user where N is the list size — keep it small (≤ 20). "
                        + "Unparseable / incomplete entries are skipped with a WARN log. Empty by default.",
                cardinality = Integer.MAX_VALUE)
        String[] visibilityProbePaths() default {};
    }

    private volatile InfralytiqsServiceCfg cfg;
    private volatile BlockingQueue<InfralytiqsAnalyticsPayload> queue = new LinkedBlockingQueue<>(4096);
    private java.net.http.HttpClient httpClient;
    private static final int MAX_BURST_ROUNDS = 256;

    private ScheduledExecutorService timer;
    private ExecutorService httpPool;
    private ScheduledFuture<?> timerTask;

    /**
     * In-memory user-profile cache. Insertion-time TTL + soft size cap. Reads on the worker thread,
     * never on a request thread.
     */
    private final ConcurrentHashMap<String, CachedProfile> profileCache = new ConcurrentHashMap<>();

    /** Sentinel used in the cache to remember "lookup failed" without re-hitting JCR every batch. */
    private static final UserProfile UNKNOWN =
            new UserProfile("", "", "", Collections.emptyList(), Collections.emptyMap());

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile ResourceResolverFactory resourceResolverFactory;

    private static final class UserProfile {
        final String userId;
        final String email;
        final String displayName;
        /** DAM folders this user can read; populated only when damVisibilityScanEnabled is true. */
        final List<String> accessibleDamFolders;
        /**
         * Tag-style visibility results derived from {@code visibilityProbePaths}: keyed by the probe's
         * eventName, value is the insertion-ordered, deduped list of matched eventValues for that name.
         * Empty when no probes are configured / no probes matched.
         */
        final Map<String, List<String>> visibilityTags;

        UserProfile(
                String userId,
                String email,
                String displayName,
                List<String> accessibleDamFolders,
                Map<String, List<String>> visibilityTags) {
            this.userId = userId == null ? "" : userId;
            this.email = email == null ? "" : email;
            this.displayName = displayName == null ? "" : displayName;
            this.accessibleDamFolders = accessibleDamFolders == null
                    ? Collections.emptyList()
                    : accessibleDamFolders;
            this.visibilityTags = visibilityTags == null
                    ? Collections.emptyMap()
                    : visibilityTags;
        }
    }

    /** Parsed form of one entry of {@code visibilityProbePaths}; immutable, validated up-front. */
    private static final class ProbeEntry {
        final String eventName;
        final String eventValue;
        final String path;

        ProbeEntry(String eventName, String eventValue, String path) {
            this.eventName = eventName;
            this.eventValue = eventValue;
            this.path = path;
        }
    }

    private static final class CachedProfile {
        final UserProfile profile;
        final long expiresAtNanos;

        CachedProfile(UserProfile profile, long expiresAtNanos) {
            this.profile = profile;
            this.expiresAtNanos = expiresAtNanos;
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static URI stripTrailingSlash(URI uri) {
        String s = uri.toString();
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return URI.create(s);
    }

    private static String enc(String raw) {
        return java.net.URLEncoder.encode(raw.trim(), StandardCharsets.UTF_8).replace("+", "%20");
    }

    private URI ingestEndpoint(InfralytiqsServiceCfg c) {
        URI base = stripTrailingSlash(URI.create(c.apiServerURI().trim()));
        String path = "/il/analytics/" + enc(c.tenantId()) + "/" + enc(c.siteId()) + "/events";
        return base.resolve(path);
    }

    @Activate
    @Modified
    synchronized void activate(InfralytiqsServiceCfg c) throws Exception {
        stopTimer();

        this.cfg = Objects.requireNonNull(c, "configuration");
        if (isBlank(c.apiServerURI()) || isBlank(c.tenantId()) || isBlank(c.siteId()) || isBlank(c.dbName())) {
            throw new IllegalArgumentException(
                    "apiServerURI, tenantId, siteId and dbName are mandatory and cannot be blank");
        }

        int cap = Math.max(512, c.queueCapacity());
        this.queue = new LinkedBlockingQueue<>(cap);

        httpClient =
                java.net.http.HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(Math.max(5, c.httpTimeoutSeconds())))
                        .sslContext(SSLContext.getDefault())
                        .build();

        int workers = Math.max(1, c.maxConcurrentPosts());
        httpPool =
                Executors.newFixedThreadPool(
                        workers,
                        r -> {
                            Thread t = new Thread(r, "infralytiqs-http-" + PID);
                            t.setDaemon(true);
                            return t;
                        });

        timer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "infralytiqs-timer-" + PID);
            t.setDaemon(true);
            return t;
        });

        long period = Math.max(250L, c.flushIntervalMs());
        timerTask =
                timer.scheduleAtFixedRate(this::scheduledDrain, period, period, TimeUnit.MILLISECONDS);

        LOG.info(
                "[{}] activated apiServerURI={}, tenant={}, site={}, db={}, batch={}, intervalMs={}, backlogCap={}, httpThreads={}",
                PID,
                c.apiServerURI(),
                c.tenantId(),
                c.siteId(),
                c.dbName(),
                c.batchMaxEvents(),
                c.flushIntervalMs(),
                c.queueCapacity(),
                workers);
    }

    @Deactivate
    synchronized void deactivate() {
        stopTimer();
        List<InfralytiqsAnalyticsPayload> residual = new ArrayList<>();
        BlockingQueue<InfralytiqsAnalyticsPayload> q = queue;
        if (q != null) {
            q.drainTo(residual);
        }

        shutdownNowAwait(httpPool);
        httpPool = null;

        if (!residual.isEmpty() && cfg != null && httpClient != null) {
            try {
                postBatchSync(residual);
            } catch (Exception ex) {
                LOG.error("[{}] final flush failed: {}", PID, ex.toString(), ex);
            }
        }

        httpClient = null;
        cfg = null;
        queue = new LinkedBlockingQueue<>(1024);

        LOG.info("[{}] deactivated", PID);
    }

    private void stopTimer() {
        ScheduledFuture<?> f = timerTask;
        timerTask = null;
        if (f != null) {
            f.cancel(false);
        }

        ScheduledExecutorService tm = timer;
        timer = null;
        shutdownNowAwait(tm);
    }

    private static void shutdownNowAwait(ExecutorService svc) {
        if (svc == null) {
            return;
        }
        svc.shutdown();
        boolean finished;
        try {
            finished = svc.awaitTermination(12, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            finished = false;
        }
        if (!finished) {
            svc.shutdownNow();
            try {
                svc.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException ex2) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void scheduledDrain() {
        InfralytiqsServiceCfg live = cfg;
        ExecutorService pool = httpPool;
        BlockingQueue<InfralytiqsAnalyticsPayload> q = queue;
        if (live == null || pool == null || q == null) {
            return;
        }

        int maxBatch = Math.min(1000, Math.max(1, live.batchMaxEvents()));
        List<InfralytiqsAnalyticsPayload> batch = new ArrayList<>(maxBatch);
        q.drainTo(batch, maxBatch);
        if (!batch.isEmpty()) {
            pool.submit(() -> postBatchSync(batch));
        }

        maybePrimeFollowOn(pool, live, q, maxBatch);
    }

    private void maybePrimeFollowOn(
            ExecutorService pool,
            InfralytiqsServiceCfg live,
            BlockingQueue<InfralytiqsAnalyticsPayload> q,
            int maxBatch) {
        int rounds = 0;
        while (live == cfg && !q.isEmpty() && rounds++ < MAX_BURST_ROUNDS) {
            List<InfralytiqsAnalyticsPayload> burst = new ArrayList<>(maxBatch);
            q.drainTo(burst, maxBatch);
            if (burst.isEmpty()) {
                return;
            }
            pool.submit(() -> postBatchSync(burst));
        }
    }

    private void postBatchSync(List<InfralytiqsAnalyticsPayload> batch) {
        InfralytiqsServiceCfg live = cfg;
        java.net.http.HttpClient client = httpClient;
        if (live == null || client == null || batch.isEmpty()) {
            requeue(batch);
            return;
        }

        // Async enrichment runs here, on the worker thread — never on a request thread.
        List<InfralytiqsAnalyticsPayload> enriched = enrichBatch(live, batch);

        URI endpoint = ingestEndpoint(live);
        byte[] body = AnalyticsJson.toJsonArray(enriched).getBytes(StandardCharsets.UTF_8);

        java.net.http.HttpRequest req =
                java.net.http.HttpRequest.newBuilder(endpoint)
                        .timeout(Duration.ofSeconds(Math.max(1, live.httpTimeoutSeconds())))
                        .header("Accept", "application/json")
                        .header("Content-Type", "application/json; charset=UTF-8")
                        .header("X-Infralytiqs-Tenant-Id", live.tenantId())
                        .header("X-Infralytiqs-Site-Id", live.siteId())
                        .header("X-Infralytiqs-DB-Name", live.dbName())
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(body))
                        .build();

        try {
            java.net.http.HttpResponse<String> rsp =
                    client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            int code = rsp.statusCode();
            if (code >= 200 && code < 300) {
                LOG.debug("[{}] ingest OK http={} events={}", PID, code, batch.size());
                return;
            }

            LOG.warn("[{}] ingest HTTP {} → {}", PID, code, shorten(rsp.body()));
            requeue(batch);
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOG.warn("[{}] ingest transport error: {}", PID, ex.toString());
            requeue(batch);
        }
    }

    private void requeue(List<InfralytiqsAnalyticsPayload> batch) {
        BlockingQueue<InfralytiqsAnalyticsPayload> q = queue;
        if (q == null || batch == null || batch.isEmpty()) {
            return;
        }

        boolean lost = false;
        for (InfralytiqsAnalyticsPayload evt : batch) {
            if (!q.offer(evt)) {
                lost = true;
                break;
            }
        }

        if (lost) {
            LOG.warn("[{}] could not replay {} events onto backlog — queue saturated", PID, batch.size());
        }
    }

    private static String shorten(String body) {
        if (body == null) {
            return "";
        }
        return body.length() > 1024 ? body.substring(0, 1024) + "..." : body;
    }

    /**
     * Enrich each payload's lightweight {@code userIdHint} with the JCR profile (email +
     * display name). All work happens on the worker thread that called us — the request thread
     * captured the hint and moved on long ago.
     */
    private List<InfralytiqsAnalyticsPayload> enrichBatch(
            InfralytiqsServiceCfg live, List<InfralytiqsAnalyticsPayload> batch) {

        if (!live.userEnrichmentEnabled() || resourceResolverFactory == null || batch.isEmpty()) {
            return batch;
        }

        // 1) Collect distinct hints from the batch first, so we open the JCR session at most once
        //    per batch and do at most N UserManager lookups (where N is the distinct count).
        java.util.LinkedHashSet<String> distinctHints = new java.util.LinkedHashSet<>();
        for (InfralytiqsAnalyticsPayload p : batch) {
            String hint = p.userIdHint();
            if (hint != null && !hint.isEmpty() && p.userId().isEmpty()) {
                distinctHints.add(hint);
            }
        }
        if (distinctHints.isEmpty()) {
            return batch;
        }

        // 2) Resolve missing profiles, populating the cache.
        Map<String, UserProfile> resolved = resolveProfiles(live, distinctHints);

        // 3) Re-emit each payload with its (possibly enriched) identity attached.
        List<InfralytiqsAnalyticsPayload> out = new ArrayList<>(batch.size());
        for (InfralytiqsAnalyticsPayload p : batch) {
            String hint = p.userIdHint();
            if (hint == null || hint.isEmpty() || !p.userId().isEmpty()) {
                out.add(p);
                continue;
            }
            UserProfile prof = resolved.getOrDefault(hint, UNKNOWN);
            String resolvedUserId = prof.userId.isEmpty() ? hint : prof.userId;

            Map<String, String> extraDims = null;
            Map<String, Double> extraMetrics = null;
            boolean hasFolders = !prof.accessibleDamFolders.isEmpty();
            boolean hasTags = !prof.visibilityTags.isEmpty();
            if (hasFolders || hasTags) {
                extraDims = new LinkedHashMap<>(2 + prof.visibilityTags.size());
                extraMetrics = new LinkedHashMap<>(1);
                if (hasFolders) {
                    extraDims.put("accessible_dam_folders", toJsonStringArray(prof.accessibleDamFolders));
                    extraMetrics.put("accessible_dam_folder_count", (double) prof.accessibleDamFolders.size());
                }
                // Tagged probes (visibilityProbePaths): one custom_dimension per distinct eventName,
                // value is a JSON array of all matched eventValues — supports the report DSL's
                // 'contains' op so panels filter on a stable token (e.g. "ARC-DAM") rather than on
                // a brittle JCR path.
                for (Map.Entry<String, List<String>> e : prof.visibilityTags.entrySet()) {
                    extraDims.put(e.getKey(), toJsonStringArray(e.getValue()));
                }
            }

            out.add(p.withUser(resolvedUserId, prof.email, prof.displayName, extraDims, extraMetrics));
        }
        return out;
    }

    private Map<String, UserProfile> resolveProfiles(
            InfralytiqsServiceCfg live, java.util.LinkedHashSet<String> hints) {

        long now = System.nanoTime();
        Map<String, UserProfile> result = new HashMap<>(hints.size());
        java.util.LinkedHashSet<String> needsLookup = new java.util.LinkedHashSet<>();

        for (String hint : hints) {
            CachedProfile cached = profileCache.get(hint);
            if (cached != null && cached.expiresAtNanos > now) {
                result.put(hint, cached.profile);
            } else {
                needsLookup.add(hint);
            }
        }

        if (needsLookup.isEmpty()) {
            return result;
        }

        // One JCR session per batch, used for all needed lookups. Closed in the finally block.
        Map<String, Object> auth =
                Collections.singletonMap(ResourceResolverFactory.SUBSERVICE, live.userEnrichmentSubService());

        ResourceResolver rr = null;
        try {
            rr = resourceResolverFactory.getServiceResourceResolver(auth);
            UserManager userManager = userManagerOf(rr);
            if (userManager == null) {
                LOG.warn(
                        "[{}] enrichment skipped — JCR session has no UserManager (sub-service '{}')",
                        PID,
                        live.userEnrichmentSubService());
                for (String hint : needsLookup) {
                    rememberMiss(live, hint);
                    result.put(hint, UNKNOWN);
                }
                return result;
            }

            Session session = rr.adaptTo(Session.class);
            long ttlNanos = TimeUnit.SECONDS.toNanos(Math.max(1, live.userCacheTtlSeconds()));
            for (String hint : needsLookup) {
                UserProfile prof = lookupProfile(userManager, session, hint, live);
                profileCache.put(hint, new CachedProfile(prof, System.nanoTime() + ttlNanos));
                result.put(hint, prof);
            }
        } catch (LoginException ex) {
            LOG.warn(
                    "[{}] cannot acquire service-user resolver for sub-service '{}' — enrichment disabled this round: {}",
                    PID,
                    live.userEnrichmentSubService(),
                    ex.toString());
            for (String hint : needsLookup) {
                result.put(hint, UNKNOWN);
            }
        } catch (Exception ex) {
            LOG.warn("[{}] enrichment failure: {}", PID, ex.toString(), ex);
            for (String hint : needsLookup) {
                result.put(hint, UNKNOWN);
            }
        } finally {
            if (rr != null) {
                rr.close();
            }
        }

        evictIfTooLarge(live);
        return result;
    }

    private void rememberMiss(InfralytiqsServiceCfg live, String hint) {
        long ttlNanos = TimeUnit.SECONDS.toNanos(Math.max(1, live.userCacheTtlSeconds()));
        profileCache.put(hint, new CachedProfile(UNKNOWN, System.nanoTime() + ttlNanos));
    }

    private static UserManager userManagerOf(ResourceResolver rr) {
        Session session = rr.adaptTo(Session.class);
        if (session instanceof JackrabbitSession) {
            try {
                return ((JackrabbitSession) session).getUserManager();
            } catch (Exception ignored) {
                return null;
            }
        }
        return null;
    }

    private static UserProfile lookupProfile(UserManager userManager, Session session, String hint,
            InfralytiqsServiceCfg cfg) {
        try {
            Authorizable authorizable = userManager.getAuthorizable(hint);
            if (!(authorizable instanceof User)) {
                return UNKNOWN;
            }
            User user = (User) authorizable;
            String userId = user.getID();
            String email = firstString(user.getProperty("profile/email"));
            if (email.isEmpty()) {
                email = firstString(user.getProperty("./profile/email"));
            }
            String displayName = firstString(user.getProperty("profile/givenName"));
            String familyName = firstString(user.getProperty("profile/familyName"));
            if (!familyName.isEmpty()) {
                displayName = displayName.isEmpty() ? familyName : (displayName + " " + familyName);
            }

            List<String> accessibleDamFolders = Collections.emptyList();
            Map<String, List<String>> visibilityTags = Collections.emptyMap();
            if (cfg.damVisibilityScanEnabled() && session != null) {
                Set<String> principalNames = collectPrincipalNames(user);
                AccessControlManager acm = session.getAccessControlManager();
                int max = Math.max(1, cfg.damVisibilityScanMaxFolders());
                accessibleDamFolders = scanAccessibleDamFolders(session, acm, principalNames, cfg, max);
                visibilityTags = evaluateVisibilityProbes(session, acm, principalNames, cfg.visibilityProbePaths());
            }

            return new UserProfile(userId, email, displayName, accessibleDamFolders, visibilityTags);
        } catch (Exception ex) {
            return UNKNOWN;
        }
    }

    /**
     * Heuristic ACL-based scan to determine which direct children of {@code damVisibilityScanRoot}
     * the supplied user is allowed to read. Inspects effective policies on each candidate node and
     * matches access-control entries against the user's principal set (the user themselves +
     * transitive group memberships + the implicit 'everyone' principal). All work runs on the
     * service worker thread; never on a request thread.
     *
     * <p>Note: deeper paths (anything more than one level below the scan root) are <em>not</em>
     * enumerated here — use {@code visibilityProbePaths} for targeted deeper probes that emit
     * tag-style custom dimensions instead.</p>
     */
    private static List<String> scanAccessibleDamFolders(
            Session session,
            AccessControlManager acm,
            Set<String> principalNames,
            InfralytiqsServiceCfg cfg,
            int max) {
        try {
            String root = cfg.damVisibilityScanRoot();
            if (root == null || root.isEmpty() || !session.nodeExists(root)) {
                return Collections.emptyList();
            }
            Node parent = session.getNode(root);
            Set<String> visible = new LinkedHashSet<>();
            NodeIterator it = parent.getNodes();
            while (it.hasNext() && visible.size() < max) {
                Node child = it.nextNode();
                String childName = child.getName();
                if (childName.startsWith("rep:") || childName.startsWith("jcr:")) {
                    continue;
                }
                if (canRead(acm, child.getPath(), principalNames)) {
                    visible.add(child.getPath());
                }
            }
            return Collections.unmodifiableList(new ArrayList<>(visible));
        } catch (Exception ex) {
            LOG.debug("[{}] dam visibility scan failed: {}", PID, ex.toString());
            return Collections.emptyList();
        }
    }

    /**
     * Run each configured {@code visibilityProbePaths} entry as a single read-access ACL check.
     * Matches are grouped by {@code eventName} and produce, per name, an insertion-ordered &amp;
     * deduped list of {@code eventValue} tokens. Entries are typically declared most-specific
     * first (e.g. {@code /content/dam/px/arc} → {@code ARC-DAM} before {@code /content/dam} →
     * {@code GLOBAL-DAM}), and a user with access to multiple of them gets multi-value coverage
     * — report panels then filter on the dimension with the {@code contains} operator.
     *
     * <p>Each evaluation is exactly one effective-ACE lookup; cost is O(N) per uncached user
     * where N is the configured probe count. Unknown paths (e.g. an Author-only path on Publish)
     * are skipped silently. Returns an empty map when the config is empty / nothing matched.</p>
     */
    private static Map<String, List<String>> evaluateVisibilityProbes(
            Session session, AccessControlManager acm, Set<String> principalNames, String[] rawProbes) {
        List<ProbeEntry> probes = parseProbeEntries(rawProbes);
        if (probes.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, LinkedHashSet<String>> grouped = new LinkedHashMap<>();
        for (ProbeEntry probe : probes) {
            try {
                if (!session.nodeExists(probe.path)) {
                    // Common case for shared cfg between Author + Publish — only one instance
                    // hosts a given subtree.
                    continue;
                }
                if (canRead(acm, probe.path, principalNames)) {
                    grouped.computeIfAbsent(probe.eventName, k -> new LinkedHashSet<>()).add(probe.eventValue);
                }
            } catch (Exception ex) {
                LOG.debug("[{}] visibility probe failed for path={}: {}", PID, probe.path, ex.toString());
            }
        }
        if (grouped.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, List<String>> out = new LinkedHashMap<>(grouped.size());
        for (Map.Entry<String, LinkedHashSet<String>> e : grouped.entrySet()) {
            out.put(e.getKey(), Collections.unmodifiableList(new ArrayList<>(e.getValue())));
        }
        return Collections.unmodifiableMap(out);
    }

    /**
     * Parse {@code visibilityProbePaths} entries. Each raw String is a JSON object literal of
     * shape {@code {"eventName":"...","eventValue":"...","path":"/abs/jcr/path"}}; missing or
     * blank fields, non-absolute paths, and unparseable JSON are skipped with a WARN log so a
     * single bad config line cannot poison the rest of the list.
     */
    private static List<ProbeEntry> parseProbeEntries(String[] raw) {
        if (raw == null || raw.length == 0) {
            return Collections.emptyList();
        }
        List<ProbeEntry> out = new ArrayList<>(raw.length);
        for (String entry : raw) {
            if (entry == null) {
                continue;
            }
            String s = entry.trim();
            if (s.isEmpty()) {
                continue;
            }
            try {
                JsonNode n = MAPPER.readTree(s);
                if (n == null || !n.isObject()) {
                    LOG.warn(
                            "[{}] visibilityProbePaths: skipping non-object entry: {}",
                            PID,
                            s);
                    continue;
                }
                String name = n.path("eventName").asText("").trim();
                String value = n.path("eventValue").asText("").trim();
                String path = n.path("path").asText("").trim();
                if (name.isEmpty() || value.isEmpty() || path.isEmpty() || !path.startsWith("/")) {
                    LOG.warn(
                            "[{}] visibilityProbePaths: skipping entry with missing/invalid eventName, eventValue, or path: {}",
                            PID,
                            s);
                    continue;
                }
                out.add(new ProbeEntry(name, value, path));
            } catch (Exception ex) {
                LOG.warn(
                        "[{}] visibilityProbePaths: skipping unparseable entry ({}): {}",
                        PID,
                        ex.toString(),
                        s);
            }
        }
        return out;
    }

    private static Set<String> collectPrincipalNames(User user) {
        Set<String> names = new java.util.LinkedHashSet<>();
        try {
            names.add(user.getPrincipal().getName());
        } catch (Exception ignored) {
            // best effort
        }
        // Implicit principal everyone — granted to all authenticated users by AEM default policies.
        names.add("everyone");
        try {
            Iterator<Group> groups = user.memberOf();
            while (groups.hasNext()) {
                try {
                    names.add(groups.next().getPrincipal().getName());
                } catch (Exception ignored) {
                    // skip malformed group
                }
            }
        } catch (Exception ignored) {
            // best effort
        }
        return names;
    }

    /**
     * Inspect the effective ACL policies on {@code path} and decide whether the supplied principal
     * set has a read privilege. Deny entries take precedence over allow entries (standard JCR
     * resolution semantics). Falls back to "yes" only when the {@code everyone} principal is in
     * the set and no explicit ACE applies — matching AEM's default of read-for-all on /content/dam.
     */
    private static boolean canRead(AccessControlManager acm, String path, Set<String> principalNames) {
        try {
            AccessControlPolicy[] policies = acm.getEffectivePolicies(path);
            boolean allow = false;
            boolean deny = false;
            boolean matchedAny = false;
            for (AccessControlPolicy p : policies) {
                if (!(p instanceof JackrabbitAccessControlList)) {
                    continue;
                }
                for (AccessControlEntry ace : ((JackrabbitAccessControlList) p).getAccessControlEntries()) {
                    String principalName = ace.getPrincipal() == null ? null : ace.getPrincipal().getName();
                    if (principalName == null || !principalNames.contains(principalName)) {
                        continue;
                    }
                    if (!hasReadPrivilege(ace.getPrivileges())) {
                        continue;
                    }
                    matchedAny = true;
                    boolean isAllow = !(ace instanceof JackrabbitAccessControlEntry)
                            || ((JackrabbitAccessControlEntry) ace).isAllow();
                    if (isAllow) {
                        allow = true;
                    } else {
                        deny = true;
                    }
                }
            }
            if (deny) {
                return false;
            }
            if (allow) {
                return true;
            }
            // No matching ACE — defer to AEM default. /content/dam is granted to 'everyone' OOTB.
            return !matchedAny && principalNames.contains("everyone");
        } catch (Exception ex) {
            return false;
        }
    }

    private static boolean hasReadPrivilege(Privilege[] privs) {
        if (privs == null) {
            return false;
        }
        for (Privilege p : privs) {
            if (privilegeImpliesRead(p)) {
                return true;
            }
        }
        return false;
    }

    private static boolean privilegeImpliesRead(Privilege priv) {
        if (priv == null) {
            return false;
        }
        String n = priv.getName();
        if ("jcr:read".equals(n) || "jcr:all".equals(n) || "rep:readNodes".equals(n)) {
            return true;
        }
        if (priv.isAggregate()) {
            for (Privilege agg : priv.getAggregatePrivileges()) {
                if (privilegeImpliesRead(agg)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String toJsonStringArray(List<String> values) {
        StringBuilder sb = new StringBuilder(values.size() * 32);
        sb.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(escapeJson(values.get(i))).append('"');
        }
        sb.append(']');
        return sb.toString();
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0, n = value.length(); i < n; i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private static String firstString(Value[] values) {
        if (values == null || values.length == 0) {
            return "";
        }
        try {
            String s = values[0].getString();
            return s == null ? "" : s;
        } catch (Exception ex) {
            return "";
        }
    }

    private void evictIfTooLarge(InfralytiqsServiceCfg live) {
        int cap = Math.max(64, live.userCacheMaxEntries());
        if (profileCache.size() <= cap) {
            return;
        }
        int target = Math.max(cap / 2, 32);
        long now = System.nanoTime();
        // Evict expired first, then oldest-by-expiry. Cheap, no LRU tracking needed.
        Iterator<Map.Entry<String, CachedProfile>> it = profileCache.entrySet().iterator();
        while (it.hasNext() && profileCache.size() > target) {
            Map.Entry<String, CachedProfile> e = it.next();
            if (e.getValue().expiresAtNanos <= now) {
                it.remove();
            }
        }
        if (profileCache.size() <= target) {
            return;
        }
        // Still too large? Drop arbitrary entries until we're under the soft cap.
        Iterator<Map.Entry<String, CachedProfile>> it2 = profileCache.entrySet().iterator();
        while (it2.hasNext() && profileCache.size() > target) {
            it2.next();
            it2.remove();
        }
    }

    @Override
    public void enqueue(InfralytiqsAnalyticsPayload event) {
        Objects.requireNonNull(event, "event");
        InfralytiqsServiceCfg live = cfg;

        BlockingQueue<InfralytiqsAnalyticsPayload> q = queue;
        ExecutorService pool = httpPool;

        if (live == null || q == null) {
            return;
        }

        if (!q.offer(event)) {
            LOG.warn("[{}] backlog full ({}) dropping {}", PID, q.remainingCapacity(), event.eventType());
            return;
        }

        int threshold = Math.max(1, live.batchMaxEvents());
        if (pool != null && !pool.isShutdown() && q.size() >= threshold) {
            pool.submit(() -> scheduledDrainKick());
        }
    }

    private void scheduledDrainKick() {
        InfralytiqsServiceCfg live = cfg;

        BlockingQueue<InfralytiqsAnalyticsPayload> q = queue;

        ExecutorService pool = httpPool;

        if (live == null || pool == null || q == null) {

            return;
        }

        int maxBatch = Math.min(1000, Math.max(1, live.batchMaxEvents()));

        List<InfralytiqsAnalyticsPayload> batch = new ArrayList<>(maxBatch);

        q.drainTo(batch, maxBatch);

        if (!batch.isEmpty()) {
            pool.submit(() -> postBatchSync(batch));
        }

        maybePrimeFollowOn(pool, live, q, maxBatch);
    }

    @Override
    public void requestFlushAsync() {
        ExecutorService pool = httpPool;
        if (pool == null || pool.isShutdown()) {
            return;
        }

        pool.submit(this::scheduledDrainKick);
    }

    static final class AnalyticsJson {

        private AnalyticsJson() {}

        static String toJsonArray(List<InfralytiqsAnalyticsPayload> payloads) {

            StringBuilder sb = new StringBuilder(Math.min(65536, 128 + payloads.size() * 256));

            sb.append('[');

            boolean first = true;

            for (InfralytiqsAnalyticsPayload payload : payloads) {

                if (!first) {

                    sb.append(',');

                }

                first = false;

                sb.append(serialize(payload));

            }

            sb.append(']');

            return sb.toString();
        }

        private static String serialize(InfralytiqsAnalyticsPayload p) {
            StringBuilder sb = new StringBuilder(384);
            sb.append('{');
            sb.append("\"event_type\":").append(quote(p.eventType()));

            sb.append(',').append("\"event_subtype\":");
            sb.append(p.eventSubtype() == null ? "null" : quote(p.eventSubtype()));

            sb.append(',').append("\"page_url\":").append(quote(p.pageUrl()));

            sb.append(',').append("\"language_iso_code\":\"\"");
            sb.append(',').append("\"user_id\":").append(quote(p.userId()));
            sb.append(',').append("\"anonymous_id\":\"\"");
            sb.append(',').append("\"session_id\":\"\"");

            // Inject resolved profile into custom_dimensions so st-ck-server stores it as
            // queryable Map columns without altering its top-level analytics schema.
            java.util.LinkedHashMap<String, String> dims =
                    new java.util.LinkedHashMap<>(p.customDimensions());
            if (!p.userEmail().isEmpty()) {
                dims.put("user_email", p.userEmail());
            }
            if (!p.displayName().isEmpty()) {
                dims.put("user_display_name", p.displayName());
            }
            if (!p.userIdHint().isEmpty() && !p.userIdHint().equals(p.userId())) {
                dims.put("user_id_hint", p.userIdHint());
            }
            sb.append(',').append("\"custom_dimensions\":").append(stringMapJson(dims));

            sb.append(',').append("\"custom_metrics\":").append(numberMapJson(p.customMetrics()));

            sb.append(',').append("\"device_type\":\"\"");
            sb.append(',').append("\"device_os\":\"\"");
            sb.append(',').append("\"utm_source\":null");

            sb.append('}');
            return sb.toString();
        }

        private static String quote(String raw) {

            StringBuilder escaped = new StringBuilder(raw.length() + 24);

            escaped.append('"');

            for (int i = 0; i < raw.length(); i++) {

                char ch = raw.charAt(i);

                switch (ch) {
                    case '"':
                        escaped.append("\\\"");
                        break;
                    case '\\':
                        escaped.append("\\\\");
                        break;

                    case '\b':
                        escaped.append("\\b");
                        break;

                    case '\f':
                        escaped.append("\\f");
                        break;

                    case '\n':
                        escaped.append("\\n");

                        break;
                    case '\r':
                        escaped.append("\\r");
                        break;
                    case '\t':
                        escaped.append("\\t");
                        break;

                    default:
                        if (ch < ' ') {
                            escaped.append("\\u").append(String.format("%04x", (int) ch));

                        } else {
                            escaped.append(ch);
                        }
                        break;
                }
            }
            escaped.append('"');
            return escaped.toString();
        }

        private static String stringMapJson(Map<String, String> map) {
            if (map == null || map.isEmpty()) {
                return "{}";
            }
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, String> e : map.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append(quote(e.getKey())).append(':').append(quote(e.getValue() == null ? "" : e.getValue()));
            }
            sb.append('}');
            return sb.toString();
        }

        private static String numberMapJson(Map<String, Double> map) {
            if (map == null || map.isEmpty()) {
                return "{}";
            }
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Double> e : map.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                Double v = e.getValue();
                sb.append(quote(e.getKey())).append(':').append(v == null ? "0.0" : Double.toString(v));
            }
            sb.append('}');
            return sb.toString();
        }
    }
}
