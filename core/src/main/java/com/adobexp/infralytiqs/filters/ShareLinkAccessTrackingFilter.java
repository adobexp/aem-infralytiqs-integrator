package com.adobexp.infralytiqs.filters;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;

import java.io.IOException;
import java.io.PrintWriter;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
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
 * <h2>Phase 1 — status-only sniffing</h2>
 *
 * <p>Phase 1 wraps the response with a tiny status-only {@link ObservationResponse} (mirroring
 * {@link DownloadTrackingFilter}) and extracts the {@code sh} query parameter as
 * {@code share_token}. Zero per-byte overhead and zero risk of perturbing the response payload.
 *
 * <h2>Phase 2 — optional HTML body inspection for {@code data-linkshare-path="…"} extraction</h2>
 *
 * <p>Phase 2 adds an opt-in body inspection path that extracts the list of shared asset paths
 * from the rendered HTML. Enabled per-rule via {@code inspect_response_body=true}.
 *
 * <p>The rendered {@code /linkshare.html} page server-side encodes every shared asset twice — as
 * {@code data-foundation-collection-item-id="/content/dam/.../foo.jpeg"} and as
 * {@code data-linkshare-path="/content/dam/.../foo.jpeg"} — on each card and on each preview
 * navigation href. Scanning for the {@code data-linkshare-path="…"} attribute is the simplest
 * stable extraction (the attribute is specifically named for the share-page use case, unlike the
 * more generic foundation-collection attribute).
 *
 * <h3>Safety contract — why this is not the download-filter incident again</h3>
 *
 * <p>The earlier {@link DownloadTrackingFilter} truncation bug happened because the response
 * wrapper returned a freshly-constructed {@code PrintWriter} chain
 * ({@code new PrintWriter(new OutputStreamWriter(new TeeServletOutputStream(super.getOutputStream(), …), enc))}).
 * That chain has its own {@code OutputStreamWriter} char-to-byte buffer that the container never
 * sees and therefore never flushes on commit — bytes written to that buffer after the last
 * explicit flush were dropped from the wire.
 *
 * <p>Phase 2 here does not do that. The body-inspecting writer ({@link TeePrintWriter}) is a
 * PrintWriter whose underlying {@code Writer} is the container-owned writer returned by
 * {@code super.getWriter()} on the response wrapper — i.e. it delegates directly to the
 * container-owned PrintWriter chain that the container will flush on commit. No intermediate
 * {@code OutputStreamWriter} ever appears between us and the underlying
 * stream. Every overridden write method calls {@code super.write(...)} (which is PrintWriter's
 * canonical {@code out.write(...)} → delegate) and then captures a side copy. Symmetrically,
 * {@link TeeServletOutputStream} writes to {@code super.getOutputStream()} first and only then
 * captures a side copy. Container flush semantics are therefore identical to Phase 1; the side
 * buffer is purely observational and cannot affect bytes on the wire.
 *
 * <h3>Performance bounds</h3>
 *
 * <ul>
 *   <li><b>Opt-in</b>. Body inspection only happens if at least one candidate rule has
 *       {@code inspect_response_body=true}. Otherwise the response is wrapped with the Phase-1
 *       status-only wrapper — no per-byte overhead, no allocation per write.</li>
 *   <li><b>Hard byte cap.</b> The side buffer never grows beyond {@code responseBufferMaxBytes}
 *       (default 256 KB; the largest realistic share landing page is ~80 KB). Once the cap is
 *       hit, further chars/bytes continue to flow through to the container's writer/stream but
 *       are no longer captured. The wire payload is always complete; only our side observation
 *       is truncated.</li>
 *   <li><b>Hard path cap.</b> The post-chain regex scan stops after
 *       {@code maxExtractedAssetPaths} (default 100) unique paths have been collected, so even a
 *       pathological response cannot turn extraction into a quadratic operation.</li>
 *   <li><b>Compiled regex.</b> The {@code data-linkshare-path="([^"]+)"} pattern is compiled once
 *       as a static field — no per-request compilation.</li>
 *   <li><b>Single-pass scan.</b> Body inspection runs after the chain on a single string copy
 *       (the toString() of the StringBuilder side buffer). For a 256 KB string this is sub-ms
 *       on modern JVMs.</li>
 * </ul>
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
 *   <li>The response wrapper is status-only by default. Body inspection requires an explicit
 *       opt-in flag on a matching rule.</li>
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

    /**
     * Compiled once at class load. The pattern matches the {@code data-linkshare-path="…"} HTML
     * attribute the AEM Asset Share landing page emits on every shared asset card. We capture the
     * value between the quotes — JCR paths cannot contain a literal {@code "} so the simple
     * {@code [^"]+} group is safe and faster than any reluctant quantifier.
     *
     * <p>Compiled with CASE_INSENSITIVE not because AEM emits mixed case (it doesn't) but as a
     * trivial guard against future markup changes that capitalise an attribute name.
     */
    private static final Pattern LINKSHARE_PATH_PATTERN =
            Pattern.compile("data-linkshare-path=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);

    @ObjectClassDefinition(
            name = "Infralytiqs Share Link Access Tracking Filter",
            description = "Felix activates this filter once a configuration PID is present and "
                    + "declares at least one valid pattern. By default the filter is strictly "
                    + "observe-only on the response side; opt-in HTML body inspection is "
                    + "available per-rule via 'inspect_response_body=true' (see the rule DSL).")
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
                                + "inspect_response_body (default false; when true the filter buffers "
                                + "the HTML response up to 'responseBufferMaxBytes' and extracts "
                                + "shared asset paths from data-linkshare-path=\"…\" attributes — "
                                + "see the class JavaDoc for the safety contract on response wrapping), "
                                + "priority (integer, lower checked first; defaults to declaration order).")
        String[] patterns() default {
                // Default rule: every successful render of /linkshare.html?sh=<token>. The 'sh'
                // query param IS the opaque share token AEM hands recipients — recording its value
                // is sufficient to correlate this view event with the matching creation event
                // captured by ShareAssetTrackingFilter (or a future server-side share-store lookup).
                // 'inspect_response_body=true' opts this rule into Phase 2 HTML body extraction
                // so the emitted event also carries 'share_paths' (csv of shared asset paths) and
                // 'share_asset_count'. See the class JavaDoc for the safety+performance contract.
                "name=pattern_1_share_link_view;subtype=share_link_view_status_200"
                        + ";url_suffix=/linkshare.html;method=GET;status=200"
                        + ";query_params_required=sh"
                        + ";query_param_dimensions=sh:share_token"
                        + ";inspect_response_body=true;priority=1"
        };

        @AttributeDefinition(
                name = "Response body buffer max bytes",
                description = "Hard cap on the in-memory response copy used by Phase 2 HTML body "
                        + "inspection. Once the buffer is full the response keeps flowing through "
                        + "to the wire unchanged — only the side observation is truncated. "
                        + "Default 262144 (256 KB); the largest realistic /linkshare.html render "
                        + "is ~80 KB.")
        int responseBufferMaxBytes() default 262144;

        @AttributeDefinition(
                name = "Max extracted asset paths",
                description = "Hard cap on how many shared asset paths Phase 2 will collect from "
                        + "one response. Bounds the work done per matching request and the size "
                        + "of the emitted 'share_paths' dimension. Default 100.")
        int maxExtractedAssetPaths() default 100;
    }

    private volatile List<ShareLinkAccessRule> rules = Collections.emptyList();
    private volatile int responseBufferMaxBytes = 262144;
    private volatile int maxExtractedAssetPaths = 100;

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
        // Floor both bounds at sensible minima so a misconfiguration can't disable extraction or
        // create a 1-byte buffer that captures nothing useful.
        this.responseBufferMaxBytes = Math.max(4096, cfg.responseBufferMaxBytes());
        this.maxExtractedAssetPaths = Math.max(1, cfg.maxExtractedAssetPaths());

        if (compiled.isEmpty()) {
            LOG.warn("[{}] no valid share-link-access tracking patterns configured — filter will match nothing", PID);
        } else {
            boolean anyBodyInspection = compiled.stream().anyMatch(r -> r.inspectResponseBody);
            LOG.info("[{}] loaded {} share-link-access tracking pattern(s); body-inspection={} (buffer cap={} bytes, path cap={})",
                    PID, compiled.size(), anyBodyInspection ? "ENABLED" : "disabled",
                    this.responseBufferMaxBytes, this.maxExtractedAssetPaths);
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

        // Decide which response wrapper to use BEFORE the chain. If no candidate asked for body
        // inspection on this request, we use the Phase-1 status-only wrapper — zero per-byte
        // overhead and behaviour is byte-for-byte identical to what already shipped. Only if a
        // candidate rule opted in do we install the Phase-2 tee writer/stream.
        boolean bodyWanted = false;
        for (ShareLinkAccessRule r : candidates) {
            if (r.inspectResponseBody) {
                bodyWanted = true;
                break;
            }
        }

        ObservationResponse mirrored = bodyWanted
                ? new BodyInspectingResponse(httpResponse, responseBufferMaxBytes)
                : new ObservationResponse(httpResponse);

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
        for (Map.Entry<String, Double> e : verdict.extractedMetrics.entrySet()) {
            b.metric(e.getKey(), e.getValue());
        }

        // Phase 2: if this verdict's rule wanted body inspection and the wrapper actually
        // captured something, run the HTML scan now and add the shared asset paths as dimensions.
        // We do the regex scan post-chain (not per-write) so the request-thread cost during the
        // response render stays trivial — the tee just appended chars to a side StringBuilder.
        if (verdict.bodyExtraction && mirrored instanceof BodyInspectingResponse) {
            BodyInspectingResponse bir = (BodyInspectingResponse) mirrored;
            extractSharedAssetPathsInto(bir.capturedBody(), maxExtractedAssetPaths, b);
        }

        ingest.enqueue(b.build());
        // INFO (not DEBUG) on purpose: this filter is brand new and the user needs an unambiguous
        // positive signal in the AEMaaCS log that interception is actually working. Volume here
        // is naturally low (one line per share-link page view) so INFO is not noisy.
        LOG.info("[{}] dispatched share-link-access analytics (pattern={}, status={})",
                PID, verdict.code, mirrored.terminalStatus());
    }

    /**
     * Pulls every {@code data-linkshare-path="…"} attribute value out of the captured HTML body
     * and stores the deduplicated, capped result as analytics dimensions / metrics on the supplied
     * builder. No-op on an empty/null body — body inspection on a degenerate response simply does
     * not add Phase-2 dimensions, leaving the event as a Phase-1-style record.
     */
    static void extractSharedAssetPathsInto(String body, int maxPaths,
            InfralytiqsAnalyticsPayload.Builder builder) {
        if (body == null || body.isEmpty()) {
            return;
        }
        // LinkedHashSet preserves first-seen order for deterministic 'share_first_path' below and
        // gives us O(1) dedup — the HTML repeats the same path on each card + on each preview
        // href, so an 80 KB page typically contains the same value 3–4 times per asset.
        Set<String> paths = new LinkedHashSet<>();
        Matcher m = LINKSHARE_PATH_PATTERN.matcher(body);
        while (m.find()) {
            if (paths.size() >= maxPaths) {
                break;
            }
            String value = m.group(1);
            if (value != null && !value.isEmpty()) {
                paths.add(value);
            }
        }

        if (paths.isEmpty()) {
            return;
        }

        // share_first_path: the lexically first path captured. Useful as a coarse pivot when the
        // share contains only one asset (the typical case in the HAR sample).
        String first = paths.iterator().next();
        builder.dimension("share_first_path", trim(first, 2048));

        builder.metric("share_asset_count", (double) paths.size());

        // share_paths: comma-separated list of all captured paths, capped to 8 KB so a pathological
        // share doesn't blow up the emitted event. ClickHouse handles String columns fine but our
        // ingestion path bounds individual dimension values to keep payloads small.
        StringBuilder csv = new StringBuilder();
        for (String p : paths) {
            if (csv.length() > 0) {
                csv.append(',');
            }
            csv.append(p);
        }
        builder.dimension("share_paths", trim(csv.toString(), 8192));
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

            return Match.of(rule.name, rule.subtype, dims, Collections.emptyMap(), rule.inspectResponseBody);
        }
        return Match.unmatched();
    }

    /** Match outcome carrier including extracted dimensions/metrics and the body-extraction flag. */
    private static final class Match {

        private static final Match NO_MATCH =
                new Match(false, "", "", Collections.emptyMap(), Collections.emptyMap(), false);

        final boolean success;
        final String code;
        final String subtype;
        final Map<String, String> extractedDimensions;
        final Map<String, Double> extractedMetrics;
        /** True iff the winning rule asked for Phase 2 HTML body extraction. */
        final boolean bodyExtraction;

        private Match(boolean success, String code, String subtype,
                Map<String, String> dims, Map<String, Double> metrics, boolean bodyExtraction) {
            this.success = success;
            this.code = code;
            this.subtype = subtype;
            this.extractedDimensions = dims;
            this.extractedMetrics = metrics;
            this.bodyExtraction = bodyExtraction;
        }

        static Match unmatched() {
            return NO_MATCH;
        }

        static Match of(String code, String subtype, Map<String, String> dims,
                Map<String, Double> metrics, boolean bodyExtraction) {
            return new Match(true, code, subtype, dims, metrics, bodyExtraction);
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
        /** When true the filter buffers the HTML response and extracts data-linkshare-path values. */
        final boolean inspectResponseBody;
        final int priority;
        int declarationOrder;

        ShareLinkAccessRule(String name, String subtype, String urlSuffix, String urlContains,
                String method, List<Integer> exactStatuses, boolean redirectBand, boolean anyStatus,
                Map<String, String> queryParamDimensions, List<String> requiredQueryParams,
                boolean inspectResponseBody, int priority) {
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
            this.inspectResponseBody = inspectResponseBody;
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
        boolean inspectResponseBody = parseBool(kv.get("inspect_response_body"), false);

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
                inspectResponseBody, priority);
    }

    private static boolean parseBool(String v, boolean dflt) {
        if (v == null || v.isEmpty()) {
            return dflt;
        }
        return "true".equalsIgnoreCase(v) || "yes".equalsIgnoreCase(v) || "1".equals(v);
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
            "inspect_response_body",
            "priority"));

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
    static class ObservationResponse extends HttpServletResponseWrapper {

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

    /**
     * Phase 2 response wrapper that does status sniffing AND captures the response body for
     * post-chain HTML extraction. The body-capture path is the careful tee design described in
     * the class JavaDoc: every byte/char written passes through to the container-owned
     * writer/stream FIRST (via {@code super.write(...)}) and only then gets copied into a side
     * buffer. The container's commit logic therefore flushes the same underlying chain it always
     * has — there is no intermediate {@code OutputStreamWriter} or {@code BufferedWriter} in the
     * flush path that the container is unaware of.
     */
    static final class BodyInspectingResponse extends ObservationResponse {

        /**
         * Hard byte cap. Capture stops growing once this is reached; writes continue to flow
         * through to the underlying response so the wire payload is unaffected.
         */
        private final int bodyCap;

        /**
         * Side buffer. Sized to {@code bodyCap} characters worst case so the StringBuilder never
         * needs to resize beyond it. Allocated lazily on the first write so a wrapped response
         * that never writes anything (e.g. an early sendError 401) costs only the wrapper object.
         */
        private StringBuilder body;

        private TeePrintWriter cachedWriter;
        private TeeServletOutputStream cachedStream;

        BodyInspectingResponse(HttpServletResponse delegate, int bodyCap) {
            super(delegate);
            this.bodyCap = bodyCap;
        }

        String capturedBody() {
            return body == null ? "" : body.toString();
        }

        // Sink invoked by the tee writer for every char actually written through to the
        // container's writer. Cheap append; cap-stop is a single comparison.
        private void captureChar(int c) {
            if (body == null) {
                body = new StringBuilder(Math.min(8192, bodyCap));
            }
            if (body.length() < bodyCap) {
                body.append((char) c);
            }
        }

        private void captureChars(char[] buf, int off, int len) {
            if (body == null) {
                body = new StringBuilder(Math.min(8192, bodyCap));
            }
            int remaining = bodyCap - body.length();
            if (remaining <= 0) {
                return;
            }
            int copy = Math.min(remaining, len);
            body.append(buf, off, copy);
        }

        private void captureString(String s, int off, int len) {
            if (body == null) {
                body = new StringBuilder(Math.min(8192, bodyCap));
            }
            int remaining = bodyCap - body.length();
            if (remaining <= 0) {
                return;
            }
            int copy = Math.min(remaining, len);
            body.append(s, off, off + copy);
        }

        // Byte-side capture used by TeeServletOutputStream. Decodes lazily via the response's
        // declared character encoding (or UTF-8 by default — Sling pages on AEMaaCS declare
        // text/html;charset=utf-8). Sub-optimal for partial multi-byte sequences but adequate
        // for an observe-only buffer — we never need round-trip fidelity here.
        private void captureBytes(byte[] buf, int off, int len) {
            if (body == null) {
                body = new StringBuilder(Math.min(8192, bodyCap));
            }
            int remaining = bodyCap - body.length();
            if (remaining <= 0) {
                return;
            }
            String enc = getCharacterEncoding();
            if (enc == null || enc.isEmpty()) {
                enc = "UTF-8";
            }
            try {
                String chunk = new String(buf, off, len, enc);
                int copy = Math.min(remaining, chunk.length());
                body.append(chunk, 0, copy);
            } catch (java.io.UnsupportedEncodingException ignored) {
                // Skip the chunk on encoding failure — better to lose observation than corrupt.
            }
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            if (cachedStream != null) {
                throw new IllegalStateException("getOutputStream() already called on response");
            }
            if (cachedWriter == null) {
                cachedWriter = new TeePrintWriter(super.getWriter(), this);
            }
            return cachedWriter;
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            if (cachedWriter != null) {
                throw new IllegalStateException("getWriter() already called on response");
            }
            if (cachedStream == null) {
                cachedStream = new TeeServletOutputStream(super.getOutputStream(), this);
            }
            return cachedStream;
        }
    }

    /**
     * PrintWriter whose underlying {@code Writer} ({@code out}) is the container-owned writer
     * returned by {@code super.getWriter()}. Every overridden write delegates to
     * {@code super.write(...)} (which immediately forwards to the container writer — PrintWriter
     * itself is not a buffered writer) and then captures the same chars to the wrapper's side
     * buffer. Container flush semantics are unchanged.
     */
    static final class TeePrintWriter extends PrintWriter {

        private final BodyInspectingResponse sink;

        TeePrintWriter(PrintWriter delegate, BodyInspectingResponse sink) {
            // autoFlush=false matches the constructor used internally by every standard servlet
            // container's getWriter() — we are wrapping, not replacing, the container's writer,
            // so we copy its flush policy.
            super(delegate, false);
            this.sink = sink;
        }

        @Override
        public void write(int c) {
            super.write(c);
            sink.captureChar(c);
        }

        @Override
        public void write(char[] buf, int off, int len) {
            super.write(buf, off, len);
            sink.captureChars(buf, off, len);
        }

        @Override
        public void write(String s, int off, int len) {
            super.write(s, off, len);
            sink.captureString(s, off, len);
        }

        // write(char[]) and write(String) inherit from PrintWriter and route through the
        // (off, len) variants above, so we capture those as well without explicit overrides.
        // print(...) and println(...) all reduce to write(String) / write(int) eventually.
    }

    /**
     * ServletOutputStream sibling of {@link TeePrintWriter}. Same contract: write to the
     * container-owned stream FIRST, then copy to the side buffer. Used only when the servlet
     * chose to render via {@code getOutputStream()} instead of {@code getWriter()} — uncommon
     * for Sling-rendered HTML but supported for completeness.
     */
    static final class TeeServletOutputStream extends ServletOutputStream {

        private final ServletOutputStream delegate;
        private final BodyInspectingResponse sink;

        TeeServletOutputStream(ServletOutputStream delegate, BodyInspectingResponse sink) {
            this.delegate = delegate;
            this.sink = sink;
        }

        @Override
        public void write(int b) throws IOException {
            delegate.write(b);
            byte[] single = {(byte) b};
            sink.captureBytes(single, 0, 1);
        }

        @Override
        public void write(byte[] b) throws IOException {
            delegate.write(b);
            sink.captureBytes(b, 0, b.length);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            delegate.write(b, off, len);
            sink.captureBytes(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            delegate.flush();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setWriteListener(WriteListener writeListener) {
            delegate.setWriteListener(writeListener);
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
