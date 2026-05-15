package com.adobexp.infralytiqs.filters;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.AuthenticationInfoPostProcessor;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

/**
 * Captures authentication events from the Sling authentication SPI.
 *
 * <p>This component plugs into Sling's {@link AuthenticationInfoPostProcessor#postProcess} hook
 * which {@code SlingAuthenticator.handleSecurity()} invokes for every successful credential
 * extraction by an {@code AuthenticationHandler} — including handlers that never produce an
 * AEM-side login URL (IMS bearer, Technical Account JWT, custom OAuth handlers, ...).
 *
 * <h2>Two emit paths</h2>
 *
 * <p><b>Path A — URL-suffix gate (existing behaviour, preserved).</b><br>
 * For requests whose URI ends with {@code /j_security_check} or {@code /saml_login}, this
 * post-processor runs the configured {@link AuthenticationTrackingFilter.MatchRule}s. These
 * Sling-handled auth URLs are short-circuited inside {@code handleSecurity()} before the
 * Sling/HTTP-Whiteboard filter chain can wrap the response, so the post-processor is the only
 * reliable observer for them.
 *
 * <p><b>Path B — Generic catch-all (new).</b><br>
 * When {@link AuthenticationTrackingFilter.AuthFilterCfg#genericAuthEnabled()} is {@code true},
 * any other successful authentication (IMS / OAuth bearer / JWT / custom handler — none of which
 * hit a Sling-recognised login URL) emits a single event named
 * {@link AuthenticationTrackingFilter.AuthFilterCfg#genericAuthName()}. Per-{@link HttpSession}
 * dedup (or per-token dedup with TTL when no session exists) guarantees one event per login,
 * not one event per authenticated request.
 *
 * <p>Both paths converge on
 * {@link AuthenticationTrackingFilter#buildPayload(HttpServletRequest, String, String, String, int, String)}
 * so payload shape is identical and downstream user-profile + group enrichment via
 * {@code InfralytiqsServiceImpl} fires in either case.
 *
 * <p>Configuration is shared with {@link AuthenticationTrackingFilter} via the same OSGi PID, so
 * a single {@code com.adobexp.infralytiqs.filters.AuthenticationTrackingFilter} factory entry
 * controls both the filter and this post-processor.
 */
@Component(
        service = AuthenticationInfoPostProcessor.class,
        immediate = false,
        configurationPid = AuthenticationTrackingFilter.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE)
public final class AuthenticationCredentialsTracker implements AuthenticationInfoPostProcessor {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationCredentialsTracker.class);

    /**
     * URL suffixes that Sling's authenticator always handles inside {@code handleSecurity()},
     * short-circuiting the request before any Servlet Filter (Sling- or whiteboard-scoped) can
     * see the response. Path A handles these URIs from the configured rule set; Path B handles
     * everything else (IMS / Bearer / JWT / custom).
     */
    private static final Set<String> AUTH_SHORT_CIRCUIT_SUFFIXES =
            Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                    "/j_security_check",
                    "/saml_login")));

    /**
     * Session attribute marker used by Path B's HttpSession-bound dedup. Stores the userId of the
     * last emit so a re-authentication within the same session under a different identity still
     * fires an event.
     */
    private static final String SESSION_DEDUP_ATTR = "com.adobexp.infralytiqs.auth.tracked.userId";

    /** Hard upper bound for the stateless token-fingerprint dedup cache. */
    private static final int TOKEN_DEDUP_MAX_ENTRIES = 10_000;

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile InfralytiqsService ingestPipeline;

    /**
     * Subset of patterns this component is concerned with for Path A — only those whose URL
     * suffix is in {@link #AUTH_SHORT_CIRCUIT_SUFFIXES}. Volatile so {@link #postProcess} sees
     * a coherent snapshot.
     */
    private volatile List<AuthenticationTrackingFilter.MatchRule> rules = Collections.emptyList();

    /** Volatile snapshot of the Path B configuration. */
    private volatile GenericAuthCfg genericAuthCfg = GenericAuthCfg.DISABLED;

    /** Stateless dedup for requests with no HttpSession (Bearer / JWT / IMS). */
    private final TokenDedupCache tokenDedup = new TokenDedupCache(TOKEN_DEDUP_MAX_ENTRIES);

    @Activate
    @Modified
    protected void activate(AuthenticationTrackingFilter.AuthFilterCfg cfg) {
        applyConfig(cfg);
    }

    private void applyConfig(AuthenticationTrackingFilter.AuthFilterCfg cfg) {
        // ---------- Path A: URL-specific rules (j_security_check / saml_login) ----------
        String[] entries = cfg == null ? null : cfg.patterns();
        if (entries == null || entries.length == 0) {
            this.rules = Collections.emptyList();
        } else {
            List<AuthenticationTrackingFilter.MatchRule> compiled = new ArrayList<>(entries.length);
            for (int i = 0; i < entries.length; i++) {
                String raw = entries[i];
                if (raw == null || raw.trim().isEmpty()) {
                    continue;
                }
                try {
                    AuthenticationTrackingFilter.MatchRule rule = AuthenticationTrackingFilter.parseRule(raw);
                    rule.declarationOrder = i;
                    if (isAuthShortCircuitSuffix(rule.urlSuffix)) {
                        compiled.add(rule);
                    }
                } catch (IllegalArgumentException ex) {
                    // The filter component already logs the same parse failure; stay silent here.
                }
            }
            compiled.sort((a, b) -> {
                int byPrio = Integer.compare(a.priority, b.priority);
                return byPrio != 0 ? byPrio : Integer.compare(a.declarationOrder, b.declarationOrder);
            });
            this.rules = Collections.unmodifiableList(compiled);
        }

        // ---------- Path B: generic catch-all (IMS / Bearer / JWT / custom handler) ----------
        if (cfg != null && cfg.genericAuthEnabled()) {
            long ttlNanos = TimeUnit.SECONDS.toNanos(Math.max(1, cfg.genericAuthTokenDedupTtlSeconds()));
            this.genericAuthCfg = new GenericAuthCfg(
                    true,
                    fallback(cfg.genericAuthName(), "pattern_99_generic_auth"),
                    fallback(cfg.genericAuthSubtype(), "generic_auth_success"),
                    fallback(cfg.genericAuthEventType(), AuthenticationTrackingFilter.DEFAULT_EVENT_TYPE),
                    ttlNanos);
        } else {
            this.genericAuthCfg = GenericAuthCfg.DISABLED;
        }

        LOG.info(
                "[{}] post-processor active — pathA(short-circuit URL rules)={}, pathB(generic auth)={} (name={}, subtype={}, eventType={}, tokenTtl={}s)",
                AuthenticationTrackingFilter.PID,
                this.rules.size(),
                this.genericAuthCfg.enabled,
                this.genericAuthCfg.name,
                this.genericAuthCfg.subtype,
                this.genericAuthCfg.eventType,
                TimeUnit.NANOSECONDS.toSeconds(this.genericAuthCfg.dedupTtlNanos));
    }

    private static boolean isAuthShortCircuitSuffix(String urlSuffix) {
        if (urlSuffix == null) {
            return false;
        }
        for (String s : AUTH_SHORT_CIRCUIT_SUFFIXES) {
            if (s.equalsIgnoreCase(urlSuffix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isAuthShortCircuitUri(String uri) {
        for (String s : AUTH_SHORT_CIRCUIT_SUFFIXES) {
            if (AuthenticationTrackingFilter.endsWithInsensitive(uri, s)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void postProcess(AuthenticationInfo info, HttpServletRequest request, HttpServletResponse response) {
        if (info == null || request == null) {
            return;
        }

        InfralytiqsService ingest = ingestPipeline;
        if (ingest == null) {
            // No active ingest service: nothing useful to do, and we don't want to flood the log.
            return;
        }

        String userIdHint = info.getUser();
        if (isBlank(userIdHint)) {
            userIdHint = request.getRemoteUser();
        }
        if (isBlank(userIdHint)) {
            // Anonymous successful auth shouldn't really happen, but treat it as nothing-to-track.
            return;
        }

        String uri = Objects.toString(request.getRequestURI(), "");
        String method = Objects.toString(request.getMethod(), "GET");

        // ---------- Path A: configured URL-specific rule (j_security_check / saml_login) ----------
        List<AuthenticationTrackingFilter.MatchRule> snapshot = rules;
        if (!snapshot.isEmpty() && isAuthShortCircuitUri(uri)) {
            for (AuthenticationTrackingFilter.MatchRule rule : snapshot) {
                if (!rule.method.equalsIgnoreCase(method)) {
                    continue;
                }
                if (!AuthenticationTrackingFilter.endsWithInsensitive(uri, rule.urlSuffix)) {
                    continue;
                }
                if (!rule.queryParams.isEmpty()
                        && !AuthenticationTrackingFilter.allParamsHaveValue(request, rule.queryParams)) {
                    continue;
                }
                if (!rule.formParams.isEmpty()
                        && !AuthenticationTrackingFilter.allParamsHaveValue(request, rule.formParams)) {
                    continue;
                }

                int reportedStatus = rule.exactStatuses.isEmpty()
                        ? HttpServletResponse.SC_OK
                        : rule.exactStatuses.get(0);

                emit(ingest, request, rule.name, rule.subtype, rule.eventType, reportedStatus, userIdHint);
                // Mark the session/token as already-emitted so Path B doesn't double-fire on the
                // next authenticated request that share the same browser session.
                markAuthEmitted(request, userIdHint);
                return;
            }
        }

        // ---------- Path B: generic catch-all for IMS / Bearer / JWT / custom auth handlers ----------
        GenericAuthCfg gen = genericAuthCfg;
        if (!gen.enabled) {
            return;
        }
        if (!firstAuthInScope(request, userIdHint, gen)) {
            return;
        }
        emit(ingest, request, gen.name, gen.subtype, gen.eventType, HttpServletResponse.SC_OK, userIdHint);
        // firstAuthInScope() has already claimed the dedup slot (session attr or token cache);
        // Path A's markAuthEmitted() is only needed when Path A emits before Path B sees the
        // request, so we don't repeat the work here.
    }

    private void emit(InfralytiqsService ingest, HttpServletRequest request, String name, String subtype,
            String eventType, int reportedStatus, String userIdHint) {
        InfralytiqsAnalyticsPayload payload = AuthenticationTrackingFilter.buildPayload(
                request, name, subtype, eventType, reportedStatus, userIdHint);
        ingest.enqueue(payload);
        LOG.debug("[{}] post-process dispatched {} analytics ({}) for {}",
                AuthenticationTrackingFilter.PID, eventType, name, safeUserDisplay(userIdHint));
    }

    /**
     * Returns {@code true} when this is the first authenticated request we observe for the given
     * user within the relevant dedup scope:
     * <ul>
     *   <li>If the request has an {@link HttpSession}, dedup is keyed by the session attribute
     *       {@link #SESSION_DEDUP_ATTR}. Self-cleans when the session expires.</li>
     *   <li>Otherwise (Bearer JWT / IMS / Technical Account), dedup is keyed by a SHA-256
     *       fingerprint of {@code userId + Authorization-header} (or remote-IP fallback) with
     *       a configurable TTL.</li>
     * </ul>
     * Side-effect: when {@code true} is returned, the session attribute or token-cache slot is
     * claimed, so subsequent calls within the same scope will return {@code false}.
     */
    private boolean firstAuthInScope(HttpServletRequest request, String userId, GenericAuthCfg gen) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            // Sync on the per-user session to avoid racing parallel-tab requests.
            synchronized (session) {
                Object prior = session.getAttribute(SESSION_DEDUP_ATTR);
                if (userId.equals(prior)) {
                    return false;
                }
                session.setAttribute(SESSION_DEDUP_ATTR, userId);
                return true;
            }
        }
        return tokenDedup.tryClaim(tokenFingerprint(request, userId), gen.dedupTtlNanos);
    }

    /**
     * Mirrors {@link #firstAuthInScope}'s side-effect for Path A. Lets a subsequent generic-path
     * call on the same session/token short-circuit cleanly.
     */
    private void markAuthEmitted(HttpServletRequest request, String userId) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            synchronized (session) {
                session.setAttribute(SESSION_DEDUP_ATTR, userId == null ? "" : userId);
            }
            return;
        }
        // Best-effort claim with the live TTL — generic config may not be enabled but we still
        // guard against stateless re-emit in the immediate future.
        long ttl = Math.max(genericAuthCfg.dedupTtlNanos, TimeUnit.SECONDS.toNanos(60));
        tokenDedup.tryClaim(tokenFingerprint(request, userId == null ? "" : userId), ttl);
    }

    /**
     * Stable per-(user, credential) key for stateless requests. Hashes the {@code Authorization}
     * header (full bearer/token string) so token rotation or impersonation produces a fresh slot,
     * while repeated requests with the same token map to the same fingerprint. Falls back to the
     * remote IP when no Authorization header is present.
     */
    private static String tokenFingerprint(HttpServletRequest request, String userId) {
        String auth = request.getHeader("Authorization");
        if (auth != null && !auth.isEmpty()) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] h = md.digest(auth.getBytes(StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder(24);
                for (int i = 0; i < 8; i++) {
                    sb.append(String.format("%02x", h[i]));
                }
                return userId + ":auth:" + sb;
            } catch (NoSuchAlgorithmException ignored) {
                // Fall through to IP-based fallback.
            }
        }
        String remote = request.getRemoteAddr();
        return userId + ":ip:" + (remote == null ? "" : remote);
    }

    private static String safeUserDisplay(String userId) {
        if (userId == null || userId.isEmpty()) {
            return "<anonymous>";
        }
        return userId.length() > 64 ? userId.substring(0, 64).toLowerCase(Locale.ROOT) : userId;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isEmpty();
    }

    private static String fallback(String value, String defaultValue) {
        return value == null || value.trim().isEmpty() ? defaultValue : value.trim();
    }

    /** Immutable snapshot of the generic-auth (Path B) configuration. */
    private static final class GenericAuthCfg {

        static final GenericAuthCfg DISABLED = new GenericAuthCfg(
                false, "", "", "", TimeUnit.MINUTES.toNanos(30));

        final boolean enabled;
        final String name;
        final String subtype;
        final String eventType;
        final long dedupTtlNanos;

        GenericAuthCfg(boolean enabled, String name, String subtype, String eventType, long dedupTtlNanos) {
            this.enabled = enabled;
            this.name = name;
            this.subtype = subtype;
            this.eventType = eventType;
            this.dedupTtlNanos = dedupTtlNanos;
        }
    }

    /**
     * Cheap concurrent TTL+capacity bounded cache used as the stateless dedup for Path B. Entries
     * store {@code expireAtNanos}; {@link #tryClaim} treats an entry whose expiry is in the past
     * as a miss and refreshes it. Eviction is best-effort and runs on insert.
     */
    static final class TokenDedupCache {

        private final ConcurrentHashMap<String, Long> entries = new ConcurrentHashMap<>();
        private final int maxEntries;

        TokenDedupCache(int maxEntries) {
            this.maxEntries = Math.max(64, maxEntries);
        }

        boolean tryClaim(String key, long ttlNanos) {
            if (key == null) {
                return false;
            }
            long now = System.nanoTime();
            Long prior = entries.get(key);
            if (prior != null && prior > now) {
                return false;
            }
            entries.put(key, now + Math.max(1L, ttlNanos));
            if (entries.size() > maxEntries) {
                evict(now);
            }
            return true;
        }

        private void evict(long now) {
            // Phase 1: drop everything already expired.
            Iterator<Map.Entry<String, Long>> it = entries.entrySet().iterator();
            while (it.hasNext() && entries.size() > maxEntries) {
                Map.Entry<String, Long> e = it.next();
                if (e.getValue() <= now) {
                    it.remove();
                }
            }
            // Phase 2: still over cap → drop arbitrary entries (LRU-ish via iterator order).
            Iterator<Map.Entry<String, Long>> it2 = entries.entrySet().iterator();
            while (it2.hasNext() && entries.size() > maxEntries) {
                it2.next();
                it2.remove();
            }
        }
    }
}
