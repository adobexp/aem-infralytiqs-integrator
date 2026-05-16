package com.adobexp.infralytiqs.filters;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
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
 * Captures AEM Touch UI "Asset Share" link-creation events and dispatches them asynchronously
 * through {@link InfralytiqsService}.
 *
 * <h2>What is tracked</h2>
 *
 * <p>AEM Author exposes a generic Adobe Cloud Resource Hierarchy operations endpoint at
 * {@code POST /adobe/repository/;api=operations;t={tenant}} which receives a JSON body of MIME
 * type {@code application/vnd.adobe.asset-operation+json}. The {@code op} field in the body
 * discriminates between {@code share}, {@code unshare}, {@code copy}, {@code move} and other
 * operations; this filter focuses on {@code op=share} (i.e. public-link creation via the
 * {@code dam/gui/components/admin/publiclinkshare} clientlib).
 *
 * <p>A successful share request looks like (from a real HAR capture):
 * <pre>
 * POST /adobe/repository/;api=operations;t=1778
 * Content-Type: application/vnd.adobe.asset-operation+json
 *
 * {"op":"share",
 *  "target":[{"repo:path":"/content/dam/testdownload/photo-4.jpeg",
 *             "repo:repositoryId":"author-p107366-e2062559.adobeaemcloud.com"}],
 *  "expirationDate":"2026-05-30T20:45:23.744Z",
 *  "allowOriginalDownload":false,
 *  "allowRenditionDownload":true}
 *
 * → 200 OK
 * {"op":"share","link":"https://.../linkshare.html?sh=...","shareToken":"...","target":[...], ...}
 * </pre>
 *
 * <h2>Design — observe only, never mutate response payloads</h2>
 *
 * <p>This filter is deliberately non-invasive on the response side, mirroring the contract that
 * {@link AuthenticationTrackingFilter} and {@link DownloadTrackingFilter} converged on after the
 * download-tracking incident (where wrapping {@code getOutputStream()} / {@code getWriter()}
 * truncated the JSON response sent by AEMaaCS's asset servlets). The response wrapper here
 * ({@link ObservationResponse}) overrides <strong>only</strong> {@code setStatus},
 * {@code sendError}, {@code sendRedirect} and {@code reset} so the terminal HTTP status can be
 * observed after the chain returns. {@code getOutputStream()} / {@code getWriter()} are NEVER
 * overridden — the response stream and its commit semantics remain entirely owned by AEMaaCS.
 *
 * <p>On the request side this filter <em>does</em> buffer the JSON body when a rule asks for it
 * — but only via {@link ReplayHttpServletRequest}, which is the same proven pattern
 * {@link AuthenticationTrackingFilter} uses to inspect {@code /j_security_check} bodies. Reading
 * the request input stream once, caching the bytes and replaying them via a fresh
 * {@code ByteArrayInputStream} is benign as long as downstream code uses standard servlet APIs
 * (which Adobe's operations servlet does — it reads a small ≤1 KB JSON body synchronously).
 * Buffering is hard-capped (default 64 KB) and the rule is silently skipped if the body would
 * exceed it.
 *
 * <p>We therefore lose the response-side {@code link} and {@code shareToken} (those would require
 * response body wrapping); we still capture op, asset path(s), repository id, expiration and the
 * download-permission booleans — i.e. everything needed to attribute "user X shared asset Y at
 * time Z with policy P" in Infralytiqs.
 *
 * <h2>Registration — OSGi HTTP Whiteboard, ALL named contexts</h2>
 *
 * <p>Unlike {@link DownloadTrackingFilter} (whose endpoints are unambiguously served by the
 * Sling main servlet under {@code /content/dam/*} and therefore bind cleanly to the named
 * whiteboard context {@code org.apache.sling}), the {@code /adobe/repository/*} endpoint is the
 * Adobe Cloud Resource Hierarchy API. It is registered into AEMaaCS by Adobe-managed bundles
 * (e.g. {@code com.adobe.granite.assetmanagement.crh.*}) and may live in a different OSGi HTTP
 * Whiteboard context than the Sling main servlet. To guarantee we observe the request regardless
 * of which named context Adobe picks for it, this component selects <em>every</em> named context
 * via {@code (osgi.http.whiteboard.context.name=*)}.
 *
 * <p>The breadth of the binding is intentionally safe because:
 * <ul>
 *   <li>Pre-match is one URI {@code containsInsensitive} check per rule per request — microseconds
 *       for non-matching requests.</li>
 *   <li>The response wrapper is status-only; nothing about the response bytes can be perturbed
 *       no matter what context the underlying servlet runs in.</li>
 *   <li>Request body buffering is gated on Content-Type, declared Content-Length and the
 *       configured byte cap — a non-matching request flows through untouched.</li>
 * </ul>
 *
 * <p>This component is declared with {@link ConfigurationPolicy#REQUIRE} and {@link #PID}.
 * Declarative Services therefore does not register the {@link Filter} service (and this filter
 * does not run) until Configuration Admin has an entry for that PID — for example a matching
 * {@code cfg.json} in the deployment package. Ingestion still requires {@link InfralytiqsService}
 * at runtime.
 */
@Component(
        service = Filter.class,
        immediate = false,
        configurationPid = ShareAssetTrackingFilter.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {
                // OSGi HTTP Whiteboard expects Servlet 3 path syntax (NOT regex). "/*" is the
                // canonical "all requests" pattern. Regex like "/.*" would be rejected as Invalid.
                "osgi.http.whiteboard.filter.pattern=/*",
                "osgi.http.whiteboard.filter.dispatcher=REQUEST",
                // Bind to EVERY named whiteboard context. The /adobe/repository API is owned by
                // Adobe-managed bundles and is not guaranteed to live in the Sling main context;
                // binding to a single named context risked silently missing the share endpoint.
                // See class JavaDoc for the safety analysis of this wider binding.
                "osgi.http.whiteboard.context.select=(osgi.http.whiteboard.context.name=*)",
                // Sit just behind DownloadTrackingFilter (9000) — both observe-only filters live
                // here so the user is already resolved on the request thread when we record.
                "service.ranking:Integer=8000"
        })
@Designate(ocd = ShareAssetTrackingFilter.ShareFilterCfg.class)
public final class ShareAssetTrackingFilter implements Filter {

    static final String PID = "com.adobexp.infralytiqs.filters.ShareAssetTrackingFilter";

    private static final Logger LOG = LoggerFactory.getLogger(ShareAssetTrackingFilter.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @ObjectClassDefinition(
            name = "Infralytiqs Share Asset Tracking Filter",
            description = "Felix activates this filter once a configuration PID is present and "
                    + "declares at least one valid pattern. The filter is observe-only on the "
                    + "response side and buffers only those request bodies whose method, URL and "
                    + "content-type match an active rule.")
    public @interface ShareFilterCfg {

        @AttributeDefinition(
                name = "Comment",
                description = "Optional textual hint for admins — unused at runtime.")
        String marker() default "";

        @AttributeDefinition(
                name = "Share-asset tracking patterns",
                description =
                        "One pattern per entry, written as 'key=value;key=value;...'. "
                                + "Recognised keys: "
                                + "name (required, used as share_tracking_pattern), "
                                + "subtype (required, used as event_subtype), "
                                + "url_suffix (case-insensitive ends-with — optional), "
                                + "url_contains (case-insensitive substring match — optional. NOTE: the "
                                + "DSL itself uses ';' as the token separator, so values must NOT contain ';'), "
                                + "method (required, e.g. POST), "
                                + "status (required: numeric code, comma-list, 'redirect', or 'any'), "
                                + "request_content_type_contains (optional, case-insensitive substring "
                                + "of the request Content-Type header), "
                                + "request_body_op (optional, matches the 'op' field in the JSON request body — "
                                + "setting this triggers request-body buffering for matched requests), "
                                + "query_params_required (comma-list of query parameter names that must be present), "
                                + "query_param_dimensions (comma-list of queryParam:dimensionName mappings), "
                                + "priority (integer, lower checked first; defaults to declaration order). "
                                + "AT LEAST ONE of {url_suffix, url_contains, request_content_type_contains, "
                                + "request_body_op} MUST be set — a rule without any discriminator would "
                                + "match every request and is rejected at activation time. "
                                + "NOTE: response-body inspection is intentionally NOT supported — see the "
                                + "DownloadTrackingFilter incident JavaDoc for why response wrapping breaks "
                                + "AEMaaCS-backed JSON endpoints.")
        String[] patterns() default {
                // Default rule deliberately has NO url_suffix / url_contains. Earlier revisions
                // tried url_suffix=/adobe/repository and then url_contains=/adobe/repository on
                // the wildcard-context binding; neither caused the filter's doFilter to fire,
                // which strongly suggests the AEM Cloud Resource Hierarchy endpoint's URI on the
                // wire — by the time it would reach Felix HTTP Whiteboard — no longer matches
                // those literal prefixes (matrix-param normalisation, dispatcher rewrites and
                // Adobe-owned servlet routing all sit between the browser and this filter).
                //
                // We therefore gate purely on what the REQUEST CARRIES: a POST with the
                // application/vnd.adobe.asset-operation+json content type whose JSON body's "op"
                // field is "share". That gate is conservative — Adobe's CRH uses this content
                // type only for asset operations, and request_body_op=share matches only
                // share-link-create calls. Status 200 OR 201 covers both AEM's documented
                // success codes for this endpoint.
                "name=pattern_1_share_by_op;subtype=share_link_create_status_2xx"
                        + ";method=POST;status=200,201"
                        + ";request_content_type_contains=asset-operation+json"
                        + ";request_body_op=share;priority=1"
        };

        @AttributeDefinition(
                name = "Request body buffer max bytes",
                description = "Hard cap on the in-memory request body copy used for JSON parsing. "
                        + "If a candidate request advertises Content-Length greater than this, "
                        + "or actually exceeds it while reading, body-dependent rules are silently "
                        + "skipped (we will not partially buffer or trim a request payload).")
        int requestBufferMaxBytes() default 65536;
    }

    private volatile List<ShareRule> rules = Collections.emptyList();
    private volatile int requestBufferMaxBytes = 65536;

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile InfralytiqsService ingestPipeline;

    @Activate
    @Modified
    protected void activate(ShareFilterCfg cfg) {
        applyConfig(cfg);
    }

    private void applyConfig(ShareFilterCfg cfg) {
        String[] entries = cfg.patterns();
        List<ShareRule> compiled = new ArrayList<>(entries == null ? 0 : entries.length);

        if (entries != null) {
            for (int i = 0; i < entries.length; i++) {
                String raw = entries[i];
                if (raw == null || raw.trim().isEmpty()) {
                    continue;
                }
                try {
                    ShareRule rule = parseRule(raw);
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
        this.requestBufferMaxBytes = Math.max(1024, cfg.requestBufferMaxBytes());

        if (compiled.isEmpty()) {
            LOG.warn("[{}] no valid share tracking patterns configured — filter will match nothing", PID);
        } else {
            LOG.info("[{}] loaded {} share tracking pattern(s); request buffer cap = {} bytes",
                    PID, compiled.size(), this.requestBufferMaxBytes);
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

        List<ShareRule> activeRules = rules;
        if (activeRules.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        List<ShareRule> candidates = preMatch(activeRules, httpRequest);
        if (candidates.isEmpty()) {
            chain.doFilter(httpRequest, httpResponse);
            return;
        }

        // Decide whether any candidate needs the JSON body buffered. We only pay the buffering
        // cost when (a) a rule explicitly wants to inspect the body AND (b) the request actually
        // carries a body the rule cares about. The wrapper itself just replays cached bytes — it
        // does not change the request shape downstream.
        ReplayHttpServletRequest buffered = null;
        for (ShareRule r : candidates) {
            if (r.needsBody() && bodyShouldBeBuffered(httpRequest, r)) {
                buffered = bufferRequest(httpRequest);
                break;
            }
        }
        HttpServletRequest effective = buffered != null ? buffered : httpRequest;

        ObservationResponse mirrored = new ObservationResponse(httpResponse);

        chain.doFilter(effective, mirrored);

        Match verdict = matchAny(candidates, effective, mirrored, buffered);
        if (!verdict.success) {
            // The URL+method pre-match found candidate rules, but downstream gating (status,
            // content-type, body op) did not produce a verdict. Emit a single line at INFO so
            // operators can see — without having to enable DEBUG on this class — that the filter
            // DID see the request but rejected it, and exactly which gate it failed (status,
            // content-type, body op). This is the primary diagnostic for "filter is registered
            // but never fires" investigations: presence of this line proves the request reached
            // doFilter and was rejected by gating; absence proves the request never reached us
            // at all (and we need a different registration mechanism).
            LOG.info("[{}] near-miss — no rule matched URI={} method={} status={} ct={} buffered-body={} (had {} candidate(s))",
                    PID, effective.getRequestURI(), effective.getMethod(),
                    mirrored.terminalStatus(),
                    Objects.toString(effective.getContentType(), ""),
                    (buffered != null && buffered.hasCachedBody()) ? buffered.cachedBody().length : -1,
                    candidates.size());
            return;
        }

        InfralytiqsService ingest = ingestPipeline;
        if (ingest == null) {
            LOG.warn("[{}] pattern {} recognised but ingestion service inactive", PID, verdict.code);
            return;
        }

        String remoteUser = effective.getRemoteUser();
        if (isBlank(remoteUser) && effective.getUserPrincipal() != null) {
            remoteUser = effective.getUserPrincipal().getName();
        }

        InfralytiqsAnalyticsPayload.Builder b =
                InfralytiqsAnalyticsPayload.builder("asset_share")
                        .eventSubtype(verdict.subtype)
                        .pageUrl(canonical(effective))
                        .lookupPath(effective.getRequestURI())
                        .userIdHint(remoteUser)
                        .dimension("share_tracking_pattern", verdict.code)
                        .dimension("http_method", effective.getMethod())
                        .dimension("http_status", Integer.toString(mirrored.terminalStatus()))
                        .dimension("request_uri", trim(effective.getRequestURI(), 1024))
                        .dimension("user_agent", trim(effective.getHeader("User-Agent"), 512))
                        .metric("share_signal", 1.0);

        for (Map.Entry<String, String> e : verdict.extractedDimensions.entrySet()) {
            b.dimension(e.getKey(), e.getValue());
        }
        for (Map.Entry<String, Double> e : verdict.extractedMetrics.entrySet()) {
            b.metric(e.getKey(), e.getValue());
        }

        ingest.enqueue(b.build());
        // INFO (not DEBUG) on purpose — symmetric with the near-miss log above so the user gets
        // an unambiguous positive signal in the AEMaaCS log that a share-create event was
        // captured. Volume is naturally low (one line per share-link creation) so INFO is fine.
        LOG.info("[{}] dispatched share analytics (pattern={}, status={})",
                PID, verdict.code, mirrored.terminalStatus());
    }

    private static List<ShareRule> preMatch(List<ShareRule> all, HttpServletRequest request) {
        String method = Objects.toString(request.getMethod(), "GET");
        String uri = Objects.toString(request.getRequestURI(), "");
        // Resolve the request Content-Type once outside the per-rule loop. We push the
        // content-type check up here (instead of leaving it only in matchAny) so that requests
        // whose Content-Type cannot match any rule exit BEFORE we allocate a candidates list, a
        // response wrapper, and — critically — BEFORE we emit the near-miss INFO log in
        // doFilter. Without this pre-filter, a URL-less rule like the default one would treat
        // every POST as a candidate and the near-miss log would fire for every unrelated POST.
        String requestCt = null;
        List<ShareRule> out = null;
        for (ShareRule r : all) {
            if (!r.method.equalsIgnoreCase(method)) {
                continue;
            }
            if (!r.urlSuffix.isEmpty() && !endsWithInsensitive(uri, r.urlSuffix)) {
                continue;
            }
            if (!r.urlContains.isEmpty() && !containsInsensitive(uri, r.urlContains)) {
                continue;
            }
            if (!r.requestContentTypeContains.isEmpty()) {
                if (requestCt == null) {
                    requestCt = Objects.toString(request.getContentType(), "");
                }
                if (!containsInsensitive(requestCt, r.requestContentTypeContains)) {
                    continue;
                }
            }
            if (out == null) {
                out = new ArrayList<>(2);
            }
            out.add(r);
        }
        return out == null ? Collections.emptyList() : out;
    }

    /**
     * Should we buffer the body for this request given this rule? The cheap pre-checks here keep
     * us from buffering unrelated requests that happen to hit a candidate URL but have the wrong
     * content-type / no body / a body bigger than the configured cap.
     */
    private boolean bodyShouldBeBuffered(HttpServletRequest request, ShareRule rule) {
        if (!rule.requestContentTypeContains.isEmpty()) {
            String ct = Objects.toString(request.getContentType(), "");
            if (!containsInsensitive(ct, rule.requestContentTypeContains)) {
                return false;
            }
        }
        int declaredLength = request.getContentLength();
        if (declaredLength == 0) {
            return false;
        }
        if (declaredLength > 0 && declaredLength > requestBufferMaxBytes) {
            LOG.debug("[{}] rule {} skipped — Content-Length {} > buffer cap {}",
                    PID, rule.name, declaredLength, requestBufferMaxBytes);
            return false;
        }
        return true;
    }

    private ReplayHttpServletRequest bufferRequest(HttpServletRequest request) throws IOException {
        Charset charset = resolveCharset(request.getCharacterEncoding());
        try {
            return ReplayHttpServletRequest.buffer(request, charset, requestBufferMaxBytes);
        } catch (BodyTooLargeException ex) {
            LOG.debug("[{}] request body exceeded buffer cap {} bytes — body-dependent rules will not fire",
                    PID, requestBufferMaxBytes);
            // Return an empty-body wrapper so the downstream chain still sees the original bytes
            // (via the wrapper's fall-through to the underlying request). In this overflow path
            // the input stream of the wrapper IS the original stream, untouched.
            return ReplayHttpServletRequest.unbuffered(request, charset);
        }
    }

    private static Match matchAny(List<ShareRule> candidates, HttpServletRequest request,
            ObservationResponse mirrored, ReplayHttpServletRequest buffered) {
        int status = mirrored.terminalStatus();
        for (ShareRule rule : candidates) {
            if (!rule.statusMatches(status)) {
                continue;
            }
            if (!rule.requiredQueryParams.isEmpty()
                    && !allQueryParamsHaveValue(request, rule.requiredQueryParams)) {
                continue;
            }
            if (!rule.requestContentTypeContains.isEmpty()) {
                String ct = Objects.toString(request.getContentType(), "");
                if (!containsInsensitive(ct, rule.requestContentTypeContains)) {
                    continue;
                }
            }

            JsonNode body = null;
            if (rule.needsBody()) {
                if (buffered == null || !buffered.hasCachedBody()) {
                    continue;
                }
                body = parseCachedJson(buffered);
                if (body == null || !body.isObject()) {
                    continue;
                }
                if (!rule.requestBodyOp.isEmpty()) {
                    JsonNode opNode = body.get("op");
                    if (opNode == null || !opNode.isValueNode()
                            || !rule.requestBodyOp.equalsIgnoreCase(opNode.asText(""))) {
                        continue;
                    }
                }
            }

            Map<String, String> dims = new LinkedHashMap<>();
            Map<String, Double> metrics = new LinkedHashMap<>();

            for (Map.Entry<String, String> mapping : rule.queryParamDimensions.entrySet()) {
                String value = request.getParameter(mapping.getKey());
                if (value != null && !value.isEmpty()) {
                    dims.put(mapping.getValue(), trim(value, 1024));
                }
            }

            if (body != null) {
                extractAssetOperationDimensions(body, dims, metrics);
            }

            return Match.of(rule.name, rule.subtype, dims, metrics);
        }
        return Match.unmatched();
    }

    /**
     * Pulls the standard fields of an {@code application/vnd.adobe.asset-operation+json} body
     * into analytics dimensions/metrics. Best-effort: any missing field is silently skipped so
     * the same routine works for share / unshare / future ops.
     *
     * <ul>
     *   <li>{@code op} → {@code share_op}</li>
     *   <li>{@code target[0]["repo:path"]} → {@code share_path}</li>
     *   <li>{@code target[*]["repo:path"]} joined → {@code share_paths} (when more than one)</li>
     *   <li>{@code target.length} → {@code share_target_count} (metric)</li>
     *   <li>{@code target[0]["repo:repositoryId"]} → {@code share_repository_id}</li>
     *   <li>{@code expirationDate} → {@code share_expiration_date}</li>
     *   <li>{@code allowOriginalDownload} → {@code share_allow_original_download}</li>
     *   <li>{@code allowRenditionDownload} → {@code share_allow_rendition_download}</li>
     * </ul>
     */
    private static void extractAssetOperationDimensions(JsonNode body,
            Map<String, String> dims, Map<String, Double> metrics) {
        JsonNode opNode = body.get("op");
        if (opNode != null && opNode.isValueNode()) {
            dims.put("share_op", trim(opNode.asText(""), 64));
        }

        JsonNode targetNode = body.get("target");
        if (targetNode != null && targetNode.isArray() && targetNode.size() > 0) {
            metrics.put("share_target_count", (double) targetNode.size());

            JsonNode firstTarget = targetNode.get(0);
            if (firstTarget != null && firstTarget.isObject()) {
                String path = stringField(firstTarget, "repo:path");
                if (!path.isEmpty()) {
                    dims.put("share_path", trim(path, 2048));
                }
                String repoId = stringField(firstTarget, "repo:repositoryId");
                if (!repoId.isEmpty()) {
                    dims.put("share_repository_id", trim(repoId, 512));
                }
            }

            if (targetNode.size() > 1) {
                StringBuilder all = new StringBuilder();
                for (int i = 0; i < targetNode.size(); i++) {
                    JsonNode t = targetNode.get(i);
                    if (t != null && t.isObject()) {
                        String p = stringField(t, "repo:path");
                        if (!p.isEmpty()) {
                            if (all.length() > 0) {
                                all.append(',');
                            }
                            all.append(p);
                        }
                    }
                }
                if (all.length() > 0) {
                    dims.put("share_paths", trim(all.toString(), 8192));
                }
            }
        }

        String expiration = stringField(body, "expirationDate");
        if (!expiration.isEmpty()) {
            dims.put("share_expiration_date", trim(expiration, 64));
        }

        if (body.has("allowOriginalDownload") && body.get("allowOriginalDownload").isBoolean()) {
            dims.put("share_allow_original_download",
                    Boolean.toString(body.get("allowOriginalDownload").asBoolean()));
        }
        if (body.has("allowRenditionDownload") && body.get("allowRenditionDownload").isBoolean()) {
            dims.put("share_allow_rendition_download",
                    Boolean.toString(body.get("allowRenditionDownload").asBoolean()));
        }
    }

    private static String stringField(JsonNode obj, String fieldName) {
        JsonNode n = obj.get(fieldName);
        if (n == null || n.isNull() || !n.isValueNode()) {
            return "";
        }
        return n.asText("");
    }

    private static JsonNode parseCachedJson(ReplayHttpServletRequest buffered) {
        byte[] body = buffered.cachedBody();
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            return MAPPER.readTree(body);
        } catch (IOException ex) {
            LOG.debug("[{}] request body is not valid JSON ({} bytes): {}", PID, body.length, ex.toString());
            return null;
        }
    }

    /** Match outcome carrier including extracted dimensions/metrics. */
    private static final class Match {

        private static final Match NO_MATCH =
                new Match(false, "", "", Collections.emptyMap(), Collections.emptyMap());

        final boolean success;
        final String code;
        final String subtype;
        final Map<String, String> extractedDimensions;
        final Map<String, Double> extractedMetrics;

        private Match(boolean success, String code, String subtype,
                Map<String, String> dims, Map<String, Double> metrics) {
            this.success = success;
            this.code = code;
            this.subtype = subtype;
            this.extractedDimensions = dims;
            this.extractedMetrics = metrics;
        }

        static Match unmatched() {
            return NO_MATCH;
        }

        static Match of(String code, String subtype, Map<String, String> dims, Map<String, Double> metrics) {
            return new Match(true, code, subtype, dims, metrics);
        }
    }

    /** Compiled, immutable representation of one configured share rule. */
    static final class ShareRule {
        final String name;
        final String subtype;
        final String urlSuffix;
        final String urlContains;
        final String method;
        final List<Integer> exactStatuses;
        final boolean redirectBand;
        final boolean anyStatus;
        final String requestContentTypeContains;
        final String requestBodyOp;
        final Map<String, String> queryParamDimensions;
        final List<String> requiredQueryParams;
        final int priority;
        int declarationOrder;

        ShareRule(String name, String subtype, String urlSuffix, String urlContains, String method,
                List<Integer> exactStatuses, boolean redirectBand, boolean anyStatus,
                String requestContentTypeContains, String requestBodyOp,
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
            this.requestContentTypeContains = requestContentTypeContains;
            this.requestBodyOp = requestBodyOp;
            this.queryParamDimensions = queryParamDimensions;
            this.requiredQueryParams = requiredQueryParams;
            this.priority = priority;
        }

        boolean needsBody() {
            return !requestBodyOp.isEmpty();
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

    static ShareRule parseRule(String raw) {
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

        rejectResponseBodyKeys(kv.keySet());

        String name = required(kv, "name");
        String subtype = required(kv, "subtype");
        String urlSuffix = kv.getOrDefault("url_suffix", "");
        String urlContains = kv.getOrDefault("url_contains", "");
        // URL match is INTENTIONALLY optional. Earlier revisions required one of url_suffix or
        // url_contains, which forced every rule to commit to a stable path prefix — and that
        // assumption broke on the AEM Cloud Resource Hierarchy endpoint
        // (POST /adobe/repository/;api=operations;t=NNNN), where the URI on the wire may already
        // have been rewritten / normalised by the time it reaches our filter and no part of the
        // declared prefix is guaranteed to be present. We therefore allow a rule that gates on
        // method + content-type + request body op alone — this is sufficient precision for the
        // CRH share-create endpoint, where the JSON request body's "op":"share" field is the true
        // discriminator. The body-op + content-type gating keeps the match conservative even
        // without a URL filter; mismatched requests still exit quickly during matchAny().
        String method = required(kv, "method").toUpperCase(Locale.ROOT);

        String requestContentTypeContains = kv.getOrDefault("request_content_type_contains", "");
        String requestBodyOp = kv.getOrDefault("request_body_op", "");
        if (urlSuffix.isEmpty() && urlContains.isEmpty()
                && requestContentTypeContains.isEmpty() && requestBodyOp.isEmpty()) {
            throw new IllegalArgumentException(
                    "rule has no discriminator — at least one of url_suffix, url_contains, "
                            + "request_content_type_contains or request_body_op must be set so we do "
                            + "not match every request");
        }

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

        return new ShareRule(name, subtype, urlSuffix, urlContains, method,
                Collections.unmodifiableList(exact), band, anyStatus,
                requestContentTypeContains, requestBodyOp,
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
            "request_content_type_contains", "request_body_op",
            "query_param_dimensions", "query_params_required",
            "priority"));

    /**
     * Response-body inspection keys are intentionally rejected — see the
     * {@link DownloadTrackingFilter} JavaDoc for the AEMaaCS-download incident they caused. We
     * fail fast rather than silently ignore them so operators do not assume body inspection works.
     */
    private static final Set<String> REJECTED_RESPONSE_BODY_KEYS = new LinkedHashSet<>(Arrays.asList(
            "response_is_json", "json_required_props", "json_string_props", "json_array_props"));

    private static void rejectResponseBodyKeys(Set<String> keys) {
        for (String k : keys) {
            if (REJECTED_RESPONSE_BODY_KEYS.contains(k)) {
                throw new IllegalArgumentException("response-body inspection key '" + k
                        + "' is not supported — see DownloadTrackingFilter JavaDoc. "
                        + "Use 'request_body_op' to inspect the JSON request body instead.");
            }
        }
    }

    private static void validateKnownKeys(Set<String> keys) {
        for (String k : keys) {
            if (!KNOWN_KEYS.contains(k)) {
                throw new IllegalArgumentException("unknown key '" + k + "' (allowed: " + KNOWN_KEYS + "). "
                        + "If you intended to embed ';' inside a value (e.g. url_contains=;api=...), "
                        + "note that ';' is the token separator — drop the leading ';' and rely on the "
                        + "remaining substring instead, e.g. url_contains=api=operations.");
            }
        }
    }

    /**
     * Status-only response wrapper. Identical contract to
     * {@link DownloadTrackingFilter.ObservationResponse}: overrides only the methods that record
     * the terminal HTTP status — {@code getOutputStream()} / {@code getWriter()} are NOT
     * overridden so the response payload remains entirely owned by AEMaaCS.
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

    /**
     * Request wrapper that consumes the original input stream once, caches the bytes, and
     * replays them on {@code getInputStream()} / {@code getReader()}. Mirrors the
     * {@code ReplayHttpServletRequest} used by {@link AuthenticationTrackingFilter} for
     * {@code j_security_check} form bodies, scoped here to JSON request bodies.
     *
     * <p>When invoked via {@link #unbuffered(HttpServletRequest, Charset)} this wrapper simply
     * delegates everything to the underlying request — used when the body is too large to buffer
     * but the rest of the filter pipeline still wants a uniform return type.
     */
    static final class ReplayHttpServletRequest extends HttpServletRequestWrapper {

        private final byte[] cache;
        private final Charset charset;

        private ReplayHttpServletRequest(HttpServletRequest delegate, byte[] body, Charset encoding) {
            super(delegate);
            this.cache = body;
            this.charset = encoding;
        }

        static ReplayHttpServletRequest buffer(HttpServletRequest downstream, Charset encoding,
                int maxBytes) throws IOException, BodyTooLargeException {
            InputStream inbound = downstream.getInputStream();
            byte[] payload = readBounded(inbound, maxBytes);
            return new ReplayHttpServletRequest(downstream, payload, encoding);
        }

        static ReplayHttpServletRequest unbuffered(HttpServletRequest downstream, Charset encoding) {
            return new ReplayHttpServletRequest(downstream, null, encoding);
        }

        boolean hasCachedBody() {
            return cache != null;
        }

        byte[] cachedBody() {
            return cache;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (cache == null) {
                return super.getInputStream();
            }
            ByteArrayInputStream stream = new ByteArrayInputStream(cache);
            return new ServletInputStream() {
                @Override
                public int read() {
                    return stream.read();
                }

                @Override
                public int read(byte[] b, int off, int len) {
                    return stream.read(b, off, len);
                }

                @Override
                public boolean isFinished() {
                    return stream.available() <= 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener readListener) {
                    throw new UnsupportedOperationException();
                }
            };
        }

        @Override
        public BufferedReader getReader() throws IOException {
            if (cache == null) {
                return super.getReader();
            }
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }

    /**
     * Reads up to {@code maxBytes} from the supplied input stream. Throws
     * {@link BodyTooLargeException} if the stream would yield more than {@code maxBytes} bytes —
     * the caller is expected to fall back to non-buffered delegation in that case so we never
     * partially serve a request body to downstream code.
     */
    static byte[] readBounded(InputStream in, int maxBytes) throws IOException, BodyTooLargeException {
        java.io.ByteArrayOutputStream sink = new java.io.ByteArrayOutputStream(Math.min(4096, maxBytes));
        byte[] chunk = new byte[Math.min(4096, maxBytes)];
        int total = 0;
        int n;
        while ((n = in.read(chunk)) != -1) {
            total += n;
            if (total > maxBytes) {
                throw new BodyTooLargeException();
            }
            sink.write(chunk, 0, n);
        }
        return sink.toByteArray();
    }

    /** Signals that the request body would exceed the configured buffer cap. */
    static final class BodyTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;
    }

    private static Charset resolveCharset(String characterEncoding) {
        if (characterEncoding == null || characterEncoding.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(characterEncoding);
        } catch (Exception unsupported) {
            return StandardCharsets.UTF_8;
        }
    }

    private static boolean endsWithInsensitive(String path, String needle) {
        if (path == null || needle == null || needle.length() > path.length()) {
            return false;
        }
        return path.regionMatches(true, path.length() - needle.length(), needle, 0, needle.length());
    }

    /**
     * Case-insensitive substring match used for URL-contains and Content-Type matching. The
     * needle is short and the haystack rarely longer than a few hundred chars, so the naïve
     * {@code toLowerCase} + {@code contains} is plenty here — no need for a Boyer-Moore-style
     * search.
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
