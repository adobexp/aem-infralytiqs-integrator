/*
 * Logging uses com.adobexp.log (via aem-loki-integrator.core) instead of org.slf4j imports.
 */
package com.adobexp.infralytiqs.service.impl;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.infralytiqs.service.TenantService;
import com.adobexp.infralytiqs.service.TenantServiceManager;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;

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

import javax.jcr.Session;
import javax.jcr.Value;
import javax.net.ssl.SSLContext;

import org.apache.jackrabbit.api.JackrabbitSession;
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

    /**
     * Custom dimension key emitted during user enrichment — JSON array of Jackrabbit principal names
     * for each {@link Group} this user declares membership in (same iterator as ACL tooling used historically).
     */
    private static final String DIM_USER_GROUPS = "user_groups";

    @ObjectClassDefinition(
            name = "Infralytiqs — analytics ingest configuration",
            description = "Operational tuning for the Infralytiqs ingestion service. The per-event "
                    + "destination (apiServerURI / tenantId / siteId / dbName) is resolved at send "
                    + "time from a matching TenantService factory configuration via "
                    + "TenantServiceManager#getConfigForPath(lookupPath). Events whose lookup path "
                    + "does not resolve to any TenantService are dropped.")
    public @interface InfralytiqsServiceCfg {

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
            new UserProfile("", "", "", Collections.emptyList());

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile ResourceResolverFactory resourceResolverFactory;

    /**
     * Mandatory reference to the tenant resolver. Per-event {@code lookupPath} is run through
     * {@link TenantServiceManager#getConfigForPath(String)} on the worker thread; the matching
     * {@link TenantService} supplies the routing tuple (apiServerURI / tenantId / siteId / dbName).
     * Events without a match are dropped.
     */
    @Reference
    private TenantServiceManager tenantServiceManager;

    private static final class UserProfile {
        final String userId;
        final String email;
        final String displayName;
        /**
         * Jackrabbit/Oak group principal identifiers from {@link User#memberOf()} (deduped, sorted lexicographically
         * for stable JSON payloads). Empty when unresolved or membership cannot be enumerated.
         */
        final List<String> memberGroupPrincipalIds;

        UserProfile(String userId, String email, String displayName, List<String> memberGroupPrincipalIds) {
            this.userId = userId == null ? "" : userId;
            this.email = email == null ? "" : email;
            this.displayName = displayName == null ? "" : displayName;
            this.memberGroupPrincipalIds = memberGroupPrincipalIds == null
                    ? Collections.emptyList()
                    : memberGroupPrincipalIds;
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

    private static URI ingestEndpoint(TenantService tenant) {
        URI base = stripTrailingSlash(URI.create(tenant.getAnalyticsServerUrl().trim()));
        String path = "/il/analytics/" + enc(tenant.getTenantId()) + "/" + enc(tenant.getSiteId()) + "/events";
        return base.resolve(path);
    }

    @Activate
    @Modified
    synchronized void activate(InfralytiqsServiceCfg c) throws Exception {
        stopTimer();

        this.cfg = Objects.requireNonNull(c, "configuration");

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
                "[{}] activated (per-event tenant routing via TenantServiceManager) batch={}, intervalMs={}, backlogCap={}, httpThreads={}",
                PID,
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
        TenantServiceManager manager = tenantServiceManager;
        if (live == null || client == null || manager == null || batch.isEmpty()) {
            requeue(batch);
            return;
        }

        // Async enrichment runs here, on the worker thread — never on a request thread.
        List<InfralytiqsAnalyticsPayload> enriched = enrichBatch(live, batch);

        // Resolve each event's tenant via TenantServiceManager.getConfigForPath(lookupPath) and
        // group events whose resolved TenantService shares the same routing tuple. Events with
        // no matching tenant are dropped (never requeued) per the integrator's contract.
        LinkedHashMap<String, TenantGroup> groups = new LinkedHashMap<>();
        int dropped = 0;
        for (InfralytiqsAnalyticsPayload evt : enriched) {
            TenantService tenant = manager.getConfigForPath(evt.lookupPath());
            if (tenant == null
                    || isBlank(tenant.getAnalyticsServerUrl())
                    || isBlank(tenant.getTenantId())
                    || isBlank(tenant.getSiteId())
                    || isBlank(tenant.getDbName())) {
                dropped++;
                continue;
            }
            String key = tenant.getAnalyticsServerUrl().trim()
                    + "|" + tenant.getTenantId().trim()
                    + "|" + tenant.getSiteId().trim()
                    + "|" + tenant.getDbName().trim();
            TenantGroup group = groups.get(key);
            if (group == null) {
                group = new TenantGroup(tenant);
                groups.put(key, group);
            }
            group.events.add(evt);
        }

        if (dropped > 0) {
            LOG.warn("[{}] dropped {} event(s) with no matching TenantService configuration", PID, dropped);
        }

        for (TenantGroup group : groups.values()) {
            sendGroup(live, client, group);
        }
    }

    private void sendGroup(InfralytiqsServiceCfg live, java.net.http.HttpClient client, TenantGroup group) {
        if (group.events.isEmpty()) {
            return;
        }
        URI endpoint = ingestEndpoint(group.tenant);
        byte[] body = AnalyticsJson.toJsonArray(group.events).getBytes(StandardCharsets.UTF_8);

        java.net.http.HttpRequest req =
                java.net.http.HttpRequest.newBuilder(endpoint)
                        .timeout(Duration.ofSeconds(Math.max(1, live.httpTimeoutSeconds())))
                        .header("Accept", "application/json")
                        .header("Content-Type", "application/json; charset=UTF-8")
                        .header("X-Infralytiqs-Tenant-Id", group.tenant.getTenantId())
                        .header("X-Infralytiqs-Site-Id", group.tenant.getSiteId())
                        .header("X-Infralytiqs-DB-Name", group.tenant.getDbName())
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(body))
                        .build();

        try {
            java.net.http.HttpResponse<String> rsp =
                    client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            int code = rsp.statusCode();
            if (code >= 200 && code < 300) {
                LOG.debug("[{}] ingest OK http={} events={} tenant={} site={}",
                        PID, code, group.events.size(), group.tenant.getTenantId(), group.tenant.getSiteId());
                return;
            }
            LOG.warn("[{}] ingest HTTP {} (tenant={} site={}) → {}",
                    PID, code, group.tenant.getTenantId(), group.tenant.getSiteId(), shorten(rsp.body()));
            requeue(group.events);
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOG.warn("[{}] ingest transport error (tenant={} site={}): {}",
                    PID, group.tenant.getTenantId(), group.tenant.getSiteId(), ex.toString());
            requeue(group.events);
        }
    }

    private static final class TenantGroup {
        final TenantService tenant;
        final List<InfralytiqsAnalyticsPayload> events = new ArrayList<>();

        TenantGroup(TenantService tenant) {
            this.tenant = tenant;
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

            // Data-layer identity: the user_id we send to ClickHouse should be the
            // authenticated user's email whenever we can determine it, so reporting
            // panels group/count on a human-readable identity instead of an opaque
            // authorizable id. Resolution order:
            //   1. Hint is already an email   -> keep it as-is (no replacement needed).
            //   2. JCR profile yields an email -> replace the id with that email.
            //   3. No email anywhere           -> fall back to the JCR authorizable id
            //                                     (or the raw hint when JCR had no match).
            String authorizableId = prof.userId.isEmpty() ? hint : prof.userId;
            String resolvedUserId;
            if (isEmailFormat(hint)) {
                resolvedUserId = hint;
            } else if (isEmailFormat(prof.email)) {
                resolvedUserId = prof.email;
            } else {
                resolvedUserId = authorizableId;
            }

            Map<String, String> extraDims = null;
            Map<String, Double> extraMetrics = null;
            if (!prof.userId.isEmpty()) {
                extraDims = new LinkedHashMap<>(1);
                extraDims.put(DIM_USER_GROUPS, toJsonStringArray(prof.memberGroupPrincipalIds));
            }

            out.add(p.withUser(resolvedUserId, prof.email, prof.displayName, extraDims, extraMetrics));
        }
        return out;
    }

    /**
     * Loose {@code <local>@<domain>.<tld>} email-shape check. Used to decide whether an
     * authenticated identity is already an email (nothing to do) or an opaque authorizable id
     * we should try to upgrade to the user's email. Deliberately permissive — we only need to
     * distinguish "looks like an email" from "is an AEM/IMS authorizable id".
     */
    private static boolean isEmailFormat(String s) {
        if (s == null) {
            return false;
        }
        String v = s.trim();
        if (v.isEmpty()) {
            return false;
        }
        int at = v.indexOf('@');
        if (at <= 0 || at != v.lastIndexOf('@') || at == v.length() - 1) {
            return false;
        }
        int dot = v.indexOf('.', at + 1);
        // a dot must exist in the domain and not be the last character (needs a TLD), and there
        // must be no whitespace anywhere in the value.
        return dot > at + 1 && dot < v.length() - 1 && v.indexOf(' ') < 0 && v.indexOf('\t') < 0;
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

            long ttlNanos = TimeUnit.SECONDS.toNanos(Math.max(1, live.userCacheTtlSeconds()));
            for (String hint : needsLookup) {
                UserProfile prof = lookupProfile(userManager, hint);
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

    private static UserProfile lookupProfile(UserManager userManager, String hint) {
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

            List<String> memberGroups = collectMemberGroupPrincipalIds(user);

            return new UserProfile(userId, email, displayName, memberGroups);
        } catch (Exception ex) {
            return UNKNOWN;
        }
    }

    /**
     * Jackrabbit/Oak group identifiers for this user (union of {@link User#declaredMemberOf()} and
     * {@link User#memberOf()}). Uses each group's {@link Authorizable#getID()} so values match authorizable
     * IDs in the security UI (e.g. {@code PG-AUTHOR-BASE}), with fallback to the Java {@code Principal} name.
     * Sorted for stable payloads; deduped.
     *
     * <p><b>Repository access:</b> the enrichment service user must have {@code jcr:read} on {@code /home/groups}
     * so Oak can resolve group authorizables during iteration. Without it, only implicit principals such as
     * {@code everyone} are typically visible.</p>
     */
    private static List<String> collectMemberGroupPrincipalIds(User user) {
        Set<String> names = new LinkedHashSet<>();
        try {
            addGroupIdsFromIterator(user.declaredMemberOf(), names);
        } catch (Exception ignored) {
            // best effort
        }
        try {
            addGroupIdsFromIterator(user.memberOf(), names);
        } catch (Exception ignored) {
            // best effort
        }
        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);
        return Collections.unmodifiableList(sorted);
    }

    private static void addGroupIdsFromIterator(Iterator<Group> groups, Set<String> into) {
        if (groups == null) {
            return;
        }
        while (groups.hasNext()) {
            Group g = groups.next();
            if (g == null) {
                continue;
            }
            try {
                String id = g.getID();
                if (id != null && !id.trim().isEmpty()) {
                    into.add(id.trim());
                    continue;
                }
            } catch (Exception ignored) {
                // fall through to principal name
            }
            try {
                String pn = g.getPrincipal() == null ? null : g.getPrincipal().getName();
                if (pn != null && !pn.trim().isEmpty()) {
                    into.add(pn.trim());
                }
            } catch (Exception ignored) {
                // skip malformed group
            }
        }
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

    /**
     * Live size of the in-memory backlog. {@link LinkedBlockingQueue#size()} is O(1) and weakly
     * consistent, which is exactly what self-pacing producers need (they only care whether the
     * backlog is "near full", not the exact count).
     */
    @Override
    public int approximateBacklogSize() {
        BlockingQueue<InfralytiqsAnalyticsPayload> q = queue;
        return q == null ? -1 : q.size();
    }

    /**
     * Total backlog capacity = current size + remaining capacity. Computed instead of stored
     * because the queue is re-created on {@code @Modified} (line 220 / 279) with a different
     * size; we never want to return a stale value.
     */
    @Override
    public int approximateBacklogCapacity() {
        BlockingQueue<InfralytiqsAnalyticsPayload> q = queue;
        if (q == null) {
            return -1;
        }
        int size = q.size();
        int remaining = q.remainingCapacity();
        // remainingCapacity is Integer.MAX_VALUE for unbounded queues; cap to avoid overflow.
        if (remaining == Integer.MAX_VALUE) {
            return Integer.MAX_VALUE;
        }
        return size + remaining;
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
