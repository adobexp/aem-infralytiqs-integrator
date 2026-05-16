package com.adobexp.infralytiqs.filters;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

/**
 * Captures AEM Touch UI "Asset Share" link-access events by observing the
 * {@code GET /linkshare.html?sh=<token>} page render that AEM serves whenever a recipient (or the
 * sharer themselves, previewing) opens a previously-generated share link.
 *
 * <h2>Why this filter exists — and why this strategy was chosen</h2>
 *
 * <p>The natural place to track share creation is the
 * {@code POST /adobe/repository/;api=operations;t={tenant}} endpoint of the Adobe Cloud Resource
 * Hierarchy (CRH) API, which is what {@link ShareAssetTrackingFilter} targets. On AEMaaCS that
 * endpoint is owned by Adobe-managed bundles (the {@code com.adobe.granite.assetmanagement.crh.*}
 * family) and the matrix-parameter URL shape (e.g. {@code ;api=operations;t=1778}) is a strong
 * signal it does not traverse the same Felix HTTP Whiteboard servlet path that the rest of AEM
 * does — empirically {@link ShareAssetTrackingFilter}'s {@code doFilter} was never invoked for
 * those URLs even with a wildcard context selector.
 *
 * <p>By contrast {@code /linkshare.html} is a vanilla Sling-rendered HTML page (the markers in
 * the response body, e.g. {@code /libs/dam/gui/content/adhocassetsharepage}, confirm a normal
 * Sling rendering pipeline). It is therefore reachable from the same OSGi HTTP Whiteboard slot
 * that {@link DownloadTrackingFilter} already proves works on AEMaaCS — and it carries the share
 * token directly in its {@code ?sh=…} query parameter. Observing this GET is sufficient to record
 * "a share link was accessed at time T by user U" attribution events.
 *
 * <h2>Phase-1 contract — pure status sniffer, no body inspection</h2>
 *
 * <p>This filter is deliberately the smallest thing that can work. It wraps the response with the
 * exact same status-only {@link ObservationResponse} the {@link DownloadTrackingFilter} uses —
 * which overrides only {@code setStatus} / {@code sendError} / {@code sendRedirect} / {@code reset}
 * and <strong>never</strong> {@code getOutputStream()} or {@code getWriter()}. Response bytes are
 * therefore physically untouched: the same incident that broke the download flow (truncation
 * caused by an OutputStreamWriter chain whose internal buffer the container never flushed) cannot
 * happen here.
 *
 * <p>Captured dimensions (Phase 1):
 * <ul>
 *   <li>{@code share_token} — the opaque {@code sh} query parameter, used to correlate the access
 *       event with the matching creation event captured by {@link ShareAssetTrackingFilter} (or
 *       any future server-side share-store lookup).</li>
 *   <li>{@code share_tracking_pattern}, {@code http_method}, {@code http_status},
 *       {@code request_uri}, {@code user_agent} — standard observability dimensions, identical to
 *       what {@link DownloadTrackingFilter} emits.</li>
 *   <li>User ID via {@code getRemoteUser()} / {@code getUserPrincipal()} when the share viewer
 *       is authenticated (the {@code /linkshare.html} HAR shows {@code x-sky-isauth: 1} — i.e. an
 *       authenticated session is the typical case on AEMaaCS author).</li>
 * </ul>
 *
 * <p>The list of shared assets is intentionally NOT extracted in Phase 1. Extracting it requires
 * either response-body parsing (the safer tee pattern on {@code super.getWriter()} is plausible
 * but still strictly more invasive than this filter) or a server-side JCR lookup of the share
 * record by token (which depends on AEM version-internal storage paths). Phase 2 will add one of
 * those once Phase 1 has proven the filter is being invoked at all in the live environment.
 *
 * <h2>Registration — OSGi HTTP Whiteboard, ALL named contexts</h2>
 *
 * <p>{@code /linkshare.html} is a Sling page so binding to the {@code org.apache.sling} named
 * context (as {@link DownloadTrackingFilter} does) would be sufficient. We deliberately go one
 * step further and bind to <em>every</em> named context via
 * {@code (osgi.http.whiteboard.context.name=*)}. The wildcard binding is safe here because:
 * <ul>
 *   <li>Pre-match is a single URI {@code endsWith} / {@code contains} check per rule per
 *       request — microseconds for non-matching requests.</li>
 *   <li>The response wrapper is status-only, so wider exposure cannot perturb response bytes for
 *       any underlying servlet in any context.</li>
 *   <li>It removes one entire class of "filter never fires because the endpoint runs in a
 *       different named context" debugging step — exactly the failure mode that frustrated the
 *       diagnosis of {@link ShareAssetTrackingFilter} on the CRH endpoint.</li>
 * </ul>
 *
 * <p>This component is declared with {@link ConfigurationPolicy#REQUIRE} and {@link #PID}.
 * Declarative Services therefore does not register the {@link Filter} service (and this filter
 * does not run) until Configuration Admin has an entry for that PID — typically a
 * {@code com.adobexp.infralytiqs.filters.ShareLinkAccessTrackingFilter.cfg.json} in the
 * deployment package. Ingestion still requires {@link InfralytiqsService} at runtime.
 */
@Component(
        service = Filter.class,
        immediate = false,
        configurationPid = ShareLinkAccessTrackingFilter.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {
                // OSGi HTTP Whiteboard expects Servlet 3 path syntax (NOT regex). "/*" is the
                // canonical "all requests" pattern. Regex like "/.*" would be rejected as Invalid.
                "osgi.http.whiteboard.filter.pattern=/*",
                "osgi.http.whiteboard.filter.dispatcher=REQUEST",
                // Bind to EVERY named whiteboard context. /linkshare.html is a Sling page so the
                // narrower (name=org.apache.sling) selector that DownloadTrackingFilter uses would
                // also work; we go wider on purpose to eliminate "wrong context" as a failure mode
                // (which is what burned ShareAssetTrackingFilter on the CRH endpoint). See JavaDoc.
                "osgi.http.whiteboard.context.select=(osgi.http.whiteboard.context.name=*)",
                // Sit just behind ShareAssetTrackingFilter (8000); all four observe-only filters
                // (Auth=10000, Download=9000, Share=8000, ShareLinkAccess=7000) cluster at the
                // tail of the chain so the request user is already resolved when we record.
                "service.ranking:Integer=7000"
        })
@Designate(ocd = ShareLinkAccessTrackingFilter.ShareLinkAccessFilterCfg.class)
public final class ShareLinkAccessTrackingFilter implements Filter {

    static final String PID = "com.adobexp.infralytiqs.filters.ShareLinkAccessTrackingFilter";

    private static final Logger LOG = LoggerFactory.getLogger(ShareLinkAccessTrackingFilter.class);

    @ObjectClassDefinition(
            name = "Infralytiqs Share Link Access Tracking Filter",
            description = "Felix activates this filter once a configuration PID is present and "
                    + "declares at least one valid pattern. The filter is strictly observe-only: "
                    + "it never modifies the request or response payload — it only records that a "
                    + "share-link page was rendered, and extracts the opaque share token from the "
                    + "query string.")
    public @interface ShareLinkAccessFilterCfg {

        @AttributeDefinition(
                name = "Comment",
                description = "Optional textual hint for admins — unused at runtime.")
        String marker() default "";

        @AttributeDefinition(
                name = "Share-link access tracking patterns",
                description =
                        "One pattern per entry, written as 'key=value;key=value;...'. "
                                + "Recognised keys: "
                                + "name (required, used as share_tracking_pattern), "
                                + "subtype (required, used as event_subtype), "
                                + "url_suffix (case-insensitive ends-with — optional), "
                                + "url_contains (case-insensitive substring match — optional; "
                                + "NOTE: the DSL uses ';' as the token separator, so values must "
                                + "NOT contain ';'), "
                                + "at least one of url_suffix or url_contains is required, "
                                + "method (required, e.g. GET), "
                                + "status (required: numeric code, comma-list, 'redirect', or 'any'), "
                                + "query_params_required (comma-list of query parameter names that "
                                + "must be present and non-empty), "
                                + "query_param_dimensions (comma-list of queryParam:dimensionName "
                                + "mappings — extracts request query string values into dimensions), "
                                + "priority (integer, lower checked first; defaults to declaration order). "
                                + "NOTE: response-body inspection is intentionally NOT supported in "
                                + "Phase 1 — see the class JavaDoc for the planned Phase 2 follow-up.")
        String[] patterns() default {
                // Default rule: every successful render of /linkshare.html?sh=<token>. The 'sh'
                // query param IS the opaque share token AEM hands recipients — recording its value
                // is sufficient to correlate this view event with the matching creation event
                // captured by ShareAssetTrackingFilter (or a future server-side share-store lookup).
                "name=pattern_1_share_link_view;subtype=share_link_view_status_200"
                        + ";url_suffix=/linkshare.html;method=GET;status=200"
                        + ";query_params_required=sh"
                        + ";query_param_dimensions=sh:share_token;priority=1"
        };
    }

    private volatile List<ShareLinkAccessRule> rules = Collections.emptyList();

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile InfralytiqsService ingestPipeline;

    @Activate
    @Modified
    protected void activate(ShareLinkAccessFilterCfg cfg) {
        applyConfig(cfg);
    }

    private void applyConfig(ShareLinkAccessFilterCfg cfg) {
        String[] entries = cfg.patterns();
        List<ShareLinkAccessRule> compiled = new ArrayList<>(entries == null ? 0 : entries.length);

        if (entries != null) {
            for (int i = 0; i < entries.length; i++) {
                String raw = entries[i];
                if (raw == null || raw.trim().isEmpty()) {
                    continue;
                }
                try {
                    ShareLinkAccessRule rule = parseRule(raw);
                    rule.declarationOrder = i;
                    compiled.add(rule);
                } catch (IllegalArgumentException ex) {
                    LOG.warn("[{}] ignoring invalid pattern entry #{} '{}': {}", PID, i, raw, ex.getMessage());
                }
            }
        }

        compiled.sort((a, b) -> {
            int byPrio = Integer.compare(a.priority, b.priority);
            return byPrio != 0 ? byPrio : Integer.compare(a.declarationOrder, b.declarationOrder);
        });

        this.rules = Collections.unmodifiableList(compiled);

        if (compiled.isEmpty()) {
            LOG.warn("[{}] no valid share-link-access tracking patterns configured — filter will match nothing", PID);
        } else {
            LOG.info("[{}] loaded {} share-link-access tracking pattern(s) (Phase 1: status-only, no body inspection)",
                    PID, compiled.size());
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void destroy() {}

    @Override
    public void doFilter(javax.servlet.ServletRequest request, javax.servlet.ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        List<ShareLinkAccessRule> activeRules = rules;
        if (activeRules.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Pre-filter rules by URL+method on the request thread BEFORE wrapping the response, so
        // that requests outside the share-link lane keep flowing through the original (unwrapped)
        // response. preMatch is a couple of microseconds per request — the wildcard context
        // binding means we see every request, but we exit early for ~all of them here.
        List<ShareLinkAccessRule> candidates = preMatch(activeRules, httpRequest);
        if (candidates.isEmpty()) {
            chain.doFilter(httpRequest, httpResponse);
            return;
        }

        ObservationResponse mirrored = new ObservationResponse(httpResponse);

        chain.doFilter(httpRequest, mirrored);

        Match verdict = matchAny(candidates, httpRequest, mirrored);
        if (!verdict.success) {
            // The URL+method pre-match found candidates, but downstream gating (status, query
            // params) did not produce a verdict. Emit a single line at DEBUG so operators can see
            // why a request that "looked like" a share view was not recorded.
            if (LOG.isDebugEnabled()) {
                LOG.debug("[{}] no rule matched URI={} method={} status={} sh-present={} (had {} candidate(s))",
                        PID, httpRequest.getRequestURI(), httpRequest.getMethod(),
                        mirrored.terminalStatus(),
                        httpRequest.getParameter("sh") != null,
                        candidates.size());
            }
            return;
        }

        InfralytiqsService ingest = ingestPipeline;
        if (ingest == null) {
            LOG.warn("[{}] pattern {} recognised but ingestion service inactive", PID, verdict.code);
            return;
        }

        // Both getRemoteUser and getUserPrincipal are populated upstream by the AEM auth handler
        // that ran *before* us in the chain — constant-time read on the request thread. On
        // AEMaaCS author this is typically the IMS-authenticated viewer; the HAR for /linkshare
        // shows x-sky-isauth=1, i.e. authenticated access is the common case.
        String remoteUser = httpRequest.getRemoteUser();
        if (isBlank(remoteUser) && httpRequest.getUserPrincipal() != null) {
            remoteUser = httpRequest.getUserPrincipal().getName();
        }

        InfralytiqsAnalyticsPayload.Builder b =
                InfralytiqsAnalyticsPayload.builder("asset_share")
                        .eventSubtype(verdict.subtype)
                        .pageUrl(canonical(httpRequest))
                        .lookupPath(httpRequest.getRequestURI())
                        .userIdHint(remoteUser)
                        .dimension("share_tracking_pattern", verdict.code)
                        .dimension("http_method", httpRequest.getMethod())
                        .dimension("http_status", Integer.toString(mirrored.terminalStatus()))
                        .dimension("request_uri", trim(httpRequest.getRequestURI(), 1024))
                        .dimension("user_agent", trim(httpRequest.getHeader("User-Agent"), 512))
                        .metric("share_view_signal", 1.0);

        for (Map.Entry<String, String> e : verdict.extractedDimensions.entrySet()) {
            b.dimension(e.getKey(), e.getValue());
        }

        ingest.enqueue(b.build());
        // INFO (not DEBUG) on purpose: this filter is brand new and the user needs an unambiguous
        // positive signal in the AEMaaCS log that interception is actually working. Volume here
        // is naturally low (one line per share-link page view) so INFO is not noisy.
        LOG.info("[{}] dispatched share-link-access analytics (pattern={}, status={})",
                PID, verdict.code, mirrored.terminalStatus());
    }

    private static List<ShareLinkAccessRule> preMatch(List<ShareLinkAccessRule> all, HttpServletRequest request) {
        String method = Objects.toString(request.getMethod(), "GET");
        String uri = Objects.toString(request.getRequestURI(), "");
        List<ShareLinkAccessRule> out = null;
        for (ShareLinkAccessRule r : all) {
            if (!r.method.equalsIgnoreCase(method)) {
                continue;
            }
            if (!r.urlSuffix.isEmpty() && !endsWithInsensitive(uri, r.urlSuffix)) {
                continue;
            }
            if (!r.urlContains.isEmpty() && !containsInsensitive(uri, r.urlContains)) {
                continue;
            }
            if (out == null) {
                out = new ArrayList<>(2);
            }
            out.add(r);
        }
        return out == null ? Collections.emptyList() : out;
    }

    private static Match matchAny(List<ShareLinkAccessRule> candidates, HttpServletRequest request,
            ObservationResponse mirrored) {
        int status = mirrored.terminalStatus();
        for (ShareLinkAccessRule rule : candidates) {
            if (!rule.statusMatches(status)) {
                continue;
            }
            if (!rule.requiredQueryParams.isEmpty()
                    && !allQueryParamsHaveValue(request, rule.requiredQueryParams)) {
                continue;
            }

            Map<String, String> dims = new LinkedHashMap<>();
            for (Map.Entry<String, String> mapping : rule.queryParamDimensions.entrySet()) {
                String value = request.getParameter(mapping.getKey());
                if (value != null && !value.isEmpty()) {
                    dims.put(mapping.getValue(), trim(value, 1024));
                }
            }

            return Match.of(rule.name, rule.subtype, dims);
        }
        return Match.unmatched();
    }

    /** Match outcome carrier including extracted dimensions. */
    private static final class Match {

        private static final Match NO_MATCH =
                new Match(false, "", "", Collections.emptyMap());

        final boolean success;
        final String code;
        final String subtype;
        final Map<String, String> extractedDimensions;

        private Match(boolean success, String code, String subtype, Map<String, String> dims) {
            this.success = success;
            this.code = code;
            this.subtype = subtype;
            this.extractedDimensions = dims;
        }

        static Match unmatched() {
            return NO_MATCH;
        }

        static Match of(String code, String subtype, Map<String, String> dims) {
            return new Match(true, code, subtype, dims);
        }
    }

    /** Compiled, immutable representation of one configured share-link-access rule. */
    static final class ShareLinkAccessRule {
        final String name;
        final String subtype;
        final String urlSuffix;
        final String urlContains;
        final String method;
        final List<Integer> exactStatuses;
        final boolean redirectBand;
        final boolean anyStatus;
        /** queryParamName -> dimensionName */
        final Map<String, String> queryParamDimensions;
        /** Query parameter names that must be present with a non-empty value for the rule to fire. */
        final List<String> requiredQueryParams;
        final int priority;
        int declarationOrder;

        ShareLinkAccessRule(String name, String subtype, String urlSuffix, String urlContains,
                String method, List<Integer> exactStatuses, boolean redirectBand, boolean anyStatus,
                Map<String, String> queryParamDimensions, List<String> requiredQueryParams,
                int priority) {
            this.name = name;
            this.subtype = subtype;
            this.urlSuffix = urlSuffix;
            this.urlContains = urlContains;
            this.method = method;
            this.exactStatuses = exactStatuses;
            this.redirectBand = redirectBand;
            this.anyStatus = anyStatus;
            this.queryParamDimensions = queryParamDimensions;
            this.requiredQueryParams = requiredQueryParams;
            this.priority = priority;
        }

        boolean statusMatches(int status) {
            if (anyStatus) {
                return true;
            }
            if (redirectBand && (status == 301 || status == 302 || status == 303 || status == 307 || status == 308)) {
                return true;
            }
            for (Integer s : exactStatuses) {
                if (s == status) {
                    return true;
                }
            }
            return false;
        }
    }

    static ShareLinkAccessRule parseRule(String raw) {
        Map<String, String> kv = new LinkedHashMap<>();
        for (String token : raw.split(";")) {
            String trimmed = token.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException("token '" + trimmed + "' is not key=value");
            }
            String key = trimmed.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            String value = trimmed.substring(eq + 1).trim();
            kv.put(key, value);
        }

        rejectBodyInspectionKeys(kv.keySet());

        String name = required(kv, "name");
        String subtype = required(kv, "subtype");
        String urlSuffix = kv.getOrDefault("url_suffix", "");
        String urlContains = kv.getOrDefault("url_contains", "");
        if (urlSuffix.isEmpty() && urlContains.isEmpty()) {
            throw new IllegalArgumentException("at least one of 'url_suffix' or 'url_contains' must be set");
        }
        String method = required(kv, "method").toUpperCase(Locale.ROOT);

        String statusSpec = required(kv, "status");
        List<Integer> exact = new ArrayList<>();
        boolean band = false;
        boolean anyStatus = false;
        for (String chunk : statusSpec.split(",")) {
            String c = chunk.trim();
            if (c.isEmpty()) {
                continue;
            }
            if ("redirect".equalsIgnoreCase(c)) {
                band = true;
                continue;
            }
            if ("any".equalsIgnoreCase(c)) {
                anyStatus = true;
                continue;
            }
            try {
                exact.add(Integer.parseInt(c));
            } catch (NumberFormatException nfe) {
                throw new IllegalArgumentException("status token '" + c + "' is not integer/redirect/any");
            }
        }
        if (!band && !anyStatus && exact.isEmpty()) {
            throw new IllegalArgumentException("status must specify at least one numeric code, 'redirect', or 'any'");
        }

        Map<String, String> queryParamDimensions = parseMappingPairs(kv.get("query_param_dimensions"));
        List<String> requiredQueryParams = csv(kv.get("query_params_required"));

        int priority = Integer.MAX_VALUE;
        String prio = kv.get("priority");
        if (prio != null && !prio.isEmpty()) {
            try {
                priority = Integer.parseInt(prio);
            } catch (NumberFormatException nfe) {
                throw new IllegalArgumentException("priority '" + prio + "' is not an integer");
            }
        }

        validateKnownKeys(kv.keySet());

        return new ShareLinkAccessRule(name, subtype, urlSuffix, urlContains, method,
                Collections.unmodifiableList(exact), band, anyStatus,
                Collections.unmodifiableMap(queryParamDimensions),
                Collections.unmodifiableList(requiredQueryParams),
                priority);
    }

    private static Map<String, String> parseMappingPairs(String csv) {
        if (csv == null || csv.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, String> out = new LinkedHashMap<>();
        for (String pair : csv.split(",")) {
            String t = pair.trim();
            if (t.isEmpty()) {
                continue;
            }
            int colon = t.indexOf(':');
            String key;
            String dim;
            if (colon < 0) {
                key = t;
                dim = t;
            } else {
                key = t.substring(0, colon).trim();
                dim = t.substring(colon + 1).trim();
            }
            if (key.isEmpty() || dim.isEmpty()) {
                throw new IllegalArgumentException("invalid mapping entry '" + t + "' (expected paramName:dimensionName)");
            }
            out.put(key, dim);
        }
        return out;
    }

    private static String required(Map<String, String> kv, String key) {
        String v = kv.get(key);
        if (v == null || v.isEmpty()) {
            throw new IllegalArgumentException("missing required key '" + key + "'");
        }
        return v;
    }

    private static List<String> csv(String value) {
        if (value == null || value.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> out = new ArrayList<>();
        for (String token : value.split(",")) {
            String t = token.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    private static final Set<String> KNOWN_KEYS = new LinkedHashSet<>(Arrays.asList(
            "name", "subtype", "url_suffix", "url_contains", "method", "status",
            "query_param_dimensions", "query_params_required",
            "priority"));

    /**
     * Phase-1 only allows the keys above. Any key that would imply body inspection (request or
     * response) is rejected at activation time so a stale config from a future Phase 2 schema
     * cannot silently leave the operator believing body extraction is happening when it is not.
     */
    private static final Set<String> REJECTED_BODY_KEYS = new LinkedHashSet<>(Arrays.asList(
            "request_body_op", "request_content_type_contains",
            "response_is_json", "response_is_html",
            "extract_share_paths_from_html",
            "html_extract_attribute"));

    private static void rejectBodyInspectionKeys(Set<String> keys) {
        for (String k : keys) {
            if (REJECTED_BODY_KEYS.contains(k)) {
                throw new IllegalArgumentException("body-inspection key '" + k
                        + "' is not supported in Phase 1 — see ShareLinkAccessTrackingFilter "
                        + "JavaDoc. Phase 2 will introduce safe HTML response inspection.");
            }
        }
    }

    private static void validateKnownKeys(Set<String> keys) {
        for (String k : keys) {
            if (!KNOWN_KEYS.contains(k)) {
                throw new IllegalArgumentException("unknown key '" + k + "' (allowed: " + KNOWN_KEYS + "). "
                        + "If you intended to embed ';' inside a value, note that ';' is the token "
                        + "separator — split your match into url_suffix + url_contains rather than "
                        + "embedding a semicolon-bearing substring.");
            }
        }
    }

    /**
     * Status-only response wrapper — same contract as
     * {@link DownloadTrackingFilter.ObservationResponse} and
     * {@link ShareAssetTrackingFilter.ObservationResponse}: overrides only the methods that record
     * the terminal HTTP status. {@code getOutputStream()} / {@code getWriter()} are NOT overridden
     * so the response payload remains entirely owned by AEMaaCS.
     */
    static final class ObservationResponse extends HttpServletResponseWrapper {

        private int status = HttpServletResponse.SC_OK;

        ObservationResponse(HttpServletResponse delegate) {
            super(delegate);
        }

        int terminalStatus() {
            return status;
        }

        @Override
        public void setStatus(int sc) {
            status = sc;
            super.setStatus(sc);
        }

        @Override
        @SuppressWarnings("deprecation")
        public void setStatus(int code, String message) {
            status = code;
            super.setStatus(code, message);
        }

        @Override
        public void sendRedirect(String location) throws IOException {
            status = HttpServletResponse.SC_FOUND;
            super.sendRedirect(location);
        }

        @Override
        public void sendError(int sc) throws IOException {
            status = sc;
            super.sendError(sc);
        }

        @Override
        public void sendError(int sc, String msg) throws IOException {
            status = sc;
            super.sendError(sc, msg);
        }

        @Override
        public void reset() {
            status = HttpServletResponse.SC_OK;
            super.reset();
        }
    }

    private static boolean endsWithInsensitive(String path, String needle) {
        if (path == null || needle == null || needle.length() > path.length()) {
            return false;
        }
        return path.regionMatches(true, path.length() - needle.length(), needle, 0, needle.length());
    }

    /**
     * Case-insensitive substring match used for URL-contains matching. Same naïve
     * {@code toLowerCase} + {@code contains} as the sibling filters — needle and haystack are both
     * short so a smarter search algorithm is not worth the complexity.
     */
    private static boolean containsInsensitive(String haystack, String needle) {
        if (haystack == null || needle == null || needle.isEmpty()) {
            return false;
        }
        return haystack.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
    }

    private static boolean allQueryParamsHaveValue(HttpServletRequest request, List<String> names) {
        for (String name : names) {
            String value = request.getParameter(name);
            if (value == null || value.isEmpty()) {
                return false;
            }
        }
        return true;
    }

    private static String trim(String candidate, int max) {
        if (candidate == null) {
            return "";
        }
        return candidate.length() <= max ? candidate : candidate.substring(0, max);
    }

    private static String canonical(HttpServletRequest request) {
        StringBuilder builder = new StringBuilder();
        String scheme = fallback(request.getScheme(), "http");
        builder.append(scheme).append("://").append(fallback(request.getServerName(), "localhost"));
        int port = request.getServerPort();
        boolean hidePort = ("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443);
        if (!hidePort) {
            builder.append(':').append(port);
        }
        builder.append(trim(request.getRequestURI(), 3072));
        String query = request.getQueryString();
        if (filled(query)) {
            builder.append('?').append(trim(query, 1536));
        }
        return builder.toString();
    }

    private static String fallback(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static boolean filled(String value) {
        return value != null && !value.isBlank();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

}
