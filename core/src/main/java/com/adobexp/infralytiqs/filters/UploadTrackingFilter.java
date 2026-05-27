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
 * Captures AEMaaCS Author Direct Binary Upload (DBU) completions described by a
 * fully-configurable list of {@link UploadRule}s and dispatches the event asynchronously through
 * {@link InfralytiqsService} so it ends up in ClickHouse via the
 * {@code POST /il/analytics/{tenantId}/{siteId}/events} endpoint of {@code st-ck-server}.
 *
 * <h2>What we observe — the AEMaaCS DBU flow</h2>
 *
 * <p>For every Touch UI asset upload the browser performs (per a HAR captured against
 * {@code author-p107366-e2062559.adobeaemcloud.com}), three URL families touch the AEM author
 * server in sequence — the actual binary {@code PUT} goes to a presigned cloud-blob URL and is
 * <em>not</em> handled by Sling, so we do not — and cannot reliably — observe it from the OSGi
 * HTTP Whiteboard:
 *
 * <ol>
 *   <li><b>{@code POST <folder>.nameconflicts.json}</b> → 200. Pre-flight check; form param
 *       {@code names} carries a JSON-array of file names. Optional bookkeeping event.</li>
 *   <li><b>{@code POST <folder>.initiateUpload.json}</b> → 200. Begins the batch upload. Form
 *       carries one {@code path} value plus N occurrences of {@code fileName} and {@code fileSize}
 *       (one pair per file in the batch). Server response carries {@code uploadURIs},
 *       {@code uploadToken}, {@code mimeType}, etc. Best signal of "user clicked Upload, N files,
 *       total X bytes".</li>
 *   <li><b>{@code POST <folder>.completeUpload.json}</b> → 200. <em>Fired once per file</em> after
 *       its blob {@code PUT} succeeds. Form carries {@code fileName}, {@code mimeType},
 *       {@code uploadToken}, {@code uploadDuration} (ms), {@code fileSize}. <strong>This is the
 *       canonical "one asset uploaded successfully" event</strong> and the primary subject of this
 *       filter — exactly one record per uploaded asset, with everything we need for analytics:
 *       folder (URL minus suffix), file name, mime, byte count, transfer duration.</li>
 * </ol>
 *
 * <h2>Strictly observe-only — same safety contract as {@link DownloadTrackingFilter}</h2>
 *
 * <p>The filter wraps the response with a tiny status-sniffing {@link ObservationResponse}
 * (mirroring the design of {@link DownloadTrackingFilter.ObservationResponse} and
 * {@link AuthenticationTrackingFilter.ObservationResponse}). The wrapper overrides only the
 * methods that record the terminal HTTP status; it never overrides {@code getOutputStream()} /
 * {@code getWriter()}, never touches request or response bytes, and therefore cannot perturb the
 * AEMaaCS DBU servlets or the asynchronous workflow they trigger after a {@code completeUpload}.
 *
 * <h2>Why we read form parameters POST-chain only</h2>
 *
 * <p>The DBU posts above are {@code application/x-www-form-urlencoded}. The Servlet container
 * lazily parses the request body into the parameter map on the first call to {@code getParameter}
 * /{@code getParameterValues}/{@code getParameterMap}. The AEMaaCS Sling servlet itself reads its
 * parameters during request processing — by the time {@code chain.doFilter()} returns, the
 * parameter map is already populated and the body InputStream has already been drained. We
 * therefore <em>only</em> call {@code getParameter*} after the chain returns. Calling those APIs
 * pre-chain would either (a) consume the InputStream out from under any servlet that reads it
 * directly, or (b) (on legacy containers) populate the parameter map at a moment AEM did not
 * expect, both of which carry breakage risk and neither of which we need.
 *
 * <h2>Registration: OSGi HTTP Whiteboard, named context {@code org.apache.sling}</h2>
 *
 * <p>The DBU URLs are Sling-rendered selectors on {@code /content/dam/...} and so live in the same
 * named whiteboard context that hosts the rest of AEM's content servlets. We therefore bind to
 * {@code (osgi.http.whiteboard.context.name=org.apache.sling)} — exactly as
 * {@link DownloadTrackingFilter} does — rather than the wildcard binding that
 * {@link ShareLinkAccessTrackingFilter} uses (which is necessary there because
 * {@code /linkshare.html} lives in a different rendering pipeline, but unnecessary here).
 *
 * <p>{@code service.ranking=8000} sits cleanly between {@link DownloadTrackingFilter} (9000) and
 * {@link ShareLinkAccessTrackingFilter} (7000); the ordering is observation-only so absolute
 * position in the chain does not matter for correctness, only for "auth handler has resolved the
 * user before we record" — which is true for any ranking below
 * {@link AuthenticationTrackingFilter}'s 10000.
 *
 * <h2>Server-side</h2>
 *
 * <p>{@code st-ck-server}'s {@code POST /il/analytics/:tenantId/:siteId/events} endpoint accepts
 * an opaque {@code event_type} string (LowCardinality column in ClickHouse) and stores arbitrary
 * dimensions/metrics in its {@code custom_dimensions} / {@code custom_metrics} {@code Map}
 * columns. No schema or controller change is required; events with
 * {@code event_type=asset_upload} flow through the same insert path the existing
 * {@code asset_download} / {@code asset_share} events do.
 *
 * <p>This component is declared with {@link ConfigurationPolicy#REQUIRE} and {@link #PID}.
 * Declarative Services therefore does not register the {@link Filter} service (and this filter
 * does not run) until Configuration Admin has an entry for that PID — typically a
 * {@code com.adobexp.infralytiqs.filters.UploadTrackingFilter.cfg.json} in the deployment
 * package. Ingestion still requires {@link InfralytiqsService} at runtime.
 */
@Component(
        service = Filter.class,
        immediate = false,
        configurationPid = UploadTrackingFilter.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {
                // OSGi HTTP Whiteboard expects Servlet 3 path syntax (NOT regex). "/*" is the
                // canonical "all requests" pattern. Regex like "/.*" would be rejected as Invalid.
                "osgi.http.whiteboard.filter.pattern=/*",
                "osgi.http.whiteboard.filter.dispatcher=REQUEST",
                // Bind to the named whiteboard context that hosts AEM's Sling main servlet — same
                // context that serves /content/dam/<folder>.{initiate,complete}Upload.json. Without
                // this selector our filter lands in the default (empty) context and is never invoked.
                "osgi.http.whiteboard.context.select=(osgi.http.whiteboard.context.name=org.apache.sling)",
                // 8000 sits between Download (9000) and ShareLinkAccess (7000). All three filters
                // observe-only and AuthenticationTrackingFilter (10000) has already resolved the
                // request user by the time any of them runs, so absolute ranking is mostly cosmetic.
                "service.ranking:Integer=8000"
        })
@Designate(ocd = UploadTrackingFilter.UploadFilterCfg.class)
public final class UploadTrackingFilter implements Filter {

    static final String PID = "com.adobexp.infralytiqs.filters.UploadTrackingFilter";

    private static final Logger LOG = LoggerFactory.getLogger(UploadTrackingFilter.class);

    /** Emitted as {@link InfralytiqsAnalyticsPayload#eventType()} for every match. */
    private static final String EVENT_TYPE = "asset_upload";

    @ObjectClassDefinition(
            name = "Infralytiqs Upload Tracking Filter",
            description = "Felix activates this sling filter once a configuration PID is present "
                    + "and declares at least one valid upload pattern. The filter is strictly "
                    + "observe-only: it never modifies the request or response payload. Form "
                    + "parameters on the AEMaaCS Direct Binary Upload POSTs (.initiateUpload.json / "
                    + ".completeUpload.json / .nameconflicts.json) are read POST-chain only, after "
                    + "the AEM servlet has already parsed them — see the class JavaDoc.")
    public @interface UploadFilterCfg {

        @AttributeDefinition(
                name = "Comment",
                description = "Optional textual hint for admins — unused at runtime.")
        String marker() default "";

        @AttributeDefinition(
                name = "Upload tracking patterns",
                description =
                        "One pattern per entry, written as 'key=value;key=value;...'. "
                                + "Recognised keys: name (required, used as upload_tracking_pattern), "
                                + "subtype (required, used as event_subtype), "
                                + "url_suffix (required, case-insensitive ends-with), "
                                + "method (required, e.g. POST), "
                                + "status (required: numeric code, comma-list, 'redirect', or 'any'), "
                                + "extract_path_from_url (default false, when true the request URI minus the suffix is emitted as 'upload_path' — the destination DAM folder), "
                                + "file_name_form_param (optional, name of a single-valued form parameter whose value is the per-file name — when set the filter emits 'upload_file_name' and 'upload_file_type' from it; typically 'fileName' on .completeUpload.json), "
                                + "query_params_required (comma-list of parameter names that must be present and non-empty for the rule to fire — getParameter sees both query string and form-urlencoded body, so this works on POST forms too), "
                                + "query_param_dimensions (comma-list of paramName:dimensionName mappings — single-value strings emitted as dimensions), "
                                + "query_param_metrics (comma-list of paramName:metricName mappings — single-value strings parsed as doubles and emitted as metrics; non-numeric values silently skipped), "
                                + "multi_param_count_metrics (comma-list of paramName:metricName mappings — emits getParameterValues(paramName).length as a metric; for batch sizing on .initiateUpload.json), "
                                + "multi_param_sum_metrics (comma-list of paramName:metricName mappings — sums numeric getParameterValues; for batch byte totals on .initiateUpload.json), "
                                + "priority (integer, lower checked first; defaults to declaration order). "
                                + "NOTE: response body inspection is intentionally NOT supported — "
                                + "see the class JavaDoc for why response wrapping breaks AEMaaCS upload flows.")
        String[] patterns() default {
                // Per-file successful completion. Fires once per uploaded asset with the destination
                // folder in the URL, the file name / mime / byte size / duration in the form body.
                // This is the primary "one asset uploaded successfully" event and the right subject
                // for almost every report panel.
                "name=pattern_1_complete_upload;subtype=post_complete_upload_status_200"
                        + ";url_suffix=.completeUpload.json;method=POST;status=200"
                        + ";extract_path_from_url=true"
                        + ";file_name_form_param=fileName"
                        + ";query_params_required=fileName"
                        + ";query_param_dimensions=mimeType:upload_mime_type"
                        + ";query_param_metrics=fileSize:upload_size_bytes,uploadDuration:upload_duration_ms"
                        + ";priority=1",
                // Batch upload initiation. Fires once per user upload gesture, before the per-file
                // PUTs start. Captures total file count and total byte size of the batch for
                // throughput / activity dashboards. The per-file 'completeUpload' record is still
                // the canonical success event; 'initiateUpload' simply gives a single row to look
                // at "how big were the upload batches the user submitted".
                "name=pattern_2_initiate_upload;subtype=post_initiate_upload_status_200"
                        + ";url_suffix=.initiateUpload.json;method=POST;status=200"
                        + ";extract_path_from_url=true"
                        + ";query_params_required=path"
                        + ";query_param_dimensions=path:upload_batch_path"
                        + ";multi_param_count_metrics=fileName:upload_batch_file_count"
                        + ";multi_param_sum_metrics=fileSize:upload_batch_total_bytes"
                        + ";priority=2",
                // Pre-flight name-conflict check. Bookkeeping event — present so dashboards can
                // separate "user merely tested whether names would conflict" from "user actually
                // uploaded". Lower priority because it is the least valuable of the three.
                "name=pattern_3_name_conflicts;subtype=post_name_conflicts_status_200"
                        + ";url_suffix=.nameconflicts.json;method=POST;status=200"
                        + ";extract_path_from_url=true"
                        + ";priority=3"
        };
    }

    private volatile List<UploadRule> rules = Collections.emptyList();

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile InfralytiqsService ingestPipeline;

    @Activate
    @Modified
    protected void activate(UploadFilterCfg cfg) {
        applyConfig(cfg);
    }

    private void applyConfig(UploadFilterCfg cfg) {
        String[] entries = cfg.patterns();
        List<UploadRule> compiled = new ArrayList<>(entries == null ? 0 : entries.length);

        if (entries != null) {
            for (int i = 0; i < entries.length; i++) {
                String raw = entries[i];
                if (raw == null || raw.trim().isEmpty()) {
                    continue;
                }
                try {
                    UploadRule rule = parseRule(raw);
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
            LOG.warn("[{}] no valid upload tracking patterns configured — filter will match nothing", PID);
        } else {
            LOG.info("[{}] loaded {} upload tracking pattern(s) (observe-only, no body inspection)",
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

        List<UploadRule> activeRules = rules;
        if (activeRules.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Pre-filter rules by URL+method on the request thread BEFORE wrapping the response, so
        // that requests outside the upload lane keep flowing through the original (unwrapped)
        // response. preMatch is a couple of microseconds per request — this cheap exit is what
        // makes a wildcard-pattern filter on a busy server effectively free.
        List<UploadRule> candidates = preMatch(activeRules, httpRequest);
        if (candidates.isEmpty()) {
            chain.doFilter(httpRequest, httpResponse);
            return;
        }

        ObservationResponse mirrored = new ObservationResponse(httpResponse);

        chain.doFilter(httpRequest, mirrored);

        // matchAny does the post-chain reads of getParameter/getParameterValues. By this point
        // the AEMaaCS DBU servlet has already populated the request's parameter map (it had to
        // in order to do its own work), so we are reading from the cache, not parsing the body.
        Match verdict = matchAny(candidates, httpRequest, mirrored);
        if (!verdict.success) {
            return;
        }

        InfralytiqsService ingest = ingestPipeline;
        if (ingest == null) {
            LOG.warn("[{}] pattern {} recognised but ingestion service inactive", PID, verdict.code);
            return;
        }

        // Both getRemoteUser and getUserPrincipal are populated upstream by the AEM auth handler
        // that ran *before* us in the chain — constant-time read on the request thread. The
        // service performs JCR profile enrichment (email + display name) asynchronously off the
        // request thread, mirroring the Download / Share filter pattern.
        String remoteUser = httpRequest.getRemoteUser();
        if (isBlank(remoteUser) && httpRequest.getUserPrincipal() != null) {
            remoteUser = httpRequest.getUserPrincipal().getName();
        }

        InfralytiqsAnalyticsPayload.Builder b =
                InfralytiqsAnalyticsPayload.builder(EVENT_TYPE)
                        .eventSubtype(verdict.subtype)
                        .pageUrl(canonical(httpRequest))
                        .lookupPath(httpRequest.getRequestURI())
                        .userIdHint(remoteUser)
                        .dimension("upload_tracking_pattern", verdict.code)
                        .dimension("http_method", httpRequest.getMethod())
                        .dimension("http_status", Integer.toString(mirrored.terminalStatus()))
                        .dimension("request_uri", trim(httpRequest.getRequestURI(), 1024))
                        .dimension("user_agent", trim(httpRequest.getHeader("User-Agent"), 512))
                        .metric("upload_signal", 1.0);

        for (Map.Entry<String, String> e : verdict.extractedDimensions.entrySet()) {
            b.dimension(e.getKey(), e.getValue());
        }
        for (Map.Entry<String, Double> e : verdict.extractedMetrics.entrySet()) {
            b.metric(e.getKey(), e.getValue());
        }

        ingest.enqueue(b.build());
        // INFO (not DEBUG) on purpose: this filter is brand new and the user needs an
        // unambiguous positive signal in the AEMaaCS log that interception is actually working.
        // Volume is naturally bounded — one line per uploaded file (completeUpload) plus one
        // per upload gesture (initiateUpload) — so INFO is not noisy.
        LOG.info("[{}] dispatched upload analytics (pattern={}, status={})",
                PID, verdict.code, mirrored.terminalStatus());
    }

    private static List<UploadRule> preMatch(List<UploadRule> all, HttpServletRequest request) {
        String method = Objects.toString(request.getMethod(), "GET");
        String uri = Objects.toString(request.getRequestURI(), "");
        List<UploadRule> out = null;
        for (UploadRule r : all) {
            if (!r.method.equalsIgnoreCase(method)) {
                continue;
            }
            if (!endsWithInsensitive(uri, r.urlSuffix)) {
                continue;
            }
            if (out == null) {
                out = new ArrayList<>(2);
            }
            out.add(r);
        }
        return out == null ? Collections.emptyList() : out;
    }

    /**
     * Resolves the winning rule and extracts every configured dimension / metric from the request.
     * Only invoked AFTER {@code chain.doFilter()} returns, so every {@code getParameter*} call
     * here reads from the parameter map already populated by the AEMaaCS DBU servlet — no body
     * parsing happens on this path, no InputStream is consumed by us.
     */
    private static Match matchAny(List<UploadRule> candidates, HttpServletRequest request,
            ObservationResponse mirrored) {
        int status = mirrored.terminalStatus();
        for (UploadRule rule : candidates) {
            if (!rule.statusMatches(status)) {
                continue;
            }
            if (!rule.requiredQueryParams.isEmpty()
                    && !allParamsHaveValue(request, rule.requiredQueryParams)) {
                continue;
            }

            Map<String, String> dims = new LinkedHashMap<>();
            Map<String, Double> metrics = new LinkedHashMap<>();

            if (rule.extractPathFromUrl) {
                String resourcePath = stripSuffix(request.getRequestURI(), rule.urlSuffix);
                if (!resourcePath.isEmpty()) {
                    dims.put("upload_path", trim(resourcePath, 2048));
                }
            }

            // Optional per-file file-name + extension extraction from a form param. This is the
            // upload analog of the download filter's URL-derived 'download_file_name' /
            // 'download_file_type' — for uploads the file name lives in the request body, not the
            // URL, so we plumb it through a dedicated config key.
            if (!rule.fileNameFormParam.isEmpty()) {
                String fileName = request.getParameter(rule.fileNameFormParam);
                if (fileName != null && !fileName.isEmpty()) {
                    dims.put("upload_file_name", trim(fileName, 512));
                    String ext = inferExtension(fileName);
                    if (!ext.isEmpty()) {
                        dims.put("upload_file_type", ext);
                    }
                }
            }

            for (Map.Entry<String, String> mapping : rule.queryParamDimensions.entrySet()) {
                String value = request.getParameter(mapping.getKey());
                if (value != null && !value.isEmpty()) {
                    dims.put(mapping.getValue(), trim(value, 1024));
                }
            }

            for (Map.Entry<String, String> mapping : rule.queryParamMetrics.entrySet()) {
                String value = request.getParameter(mapping.getKey());
                Double d = parseDoubleOrNull(value);
                if (d != null) {
                    metrics.put(mapping.getValue(), d);
                }
            }

            for (Map.Entry<String, String> mapping : rule.multiParamCountMetrics.entrySet()) {
                String[] values = request.getParameterValues(mapping.getKey());
                int count = 0;
                if (values != null) {
                    for (String v : values) {
                        if (v != null && !v.isEmpty()) {
                            count++;
                        }
                    }
                }
                metrics.put(mapping.getValue(), (double) count);
            }

            for (Map.Entry<String, String> mapping : rule.multiParamSumMetrics.entrySet()) {
                String[] values = request.getParameterValues(mapping.getKey());
                double sum = 0.0;
                if (values != null) {
                    for (String v : values) {
                        Double d = parseDoubleOrNull(v);
                        if (d != null) {
                            sum += d;
                        }
                    }
                }
                metrics.put(mapping.getValue(), sum);
            }

            return Match.of(rule.name, rule.subtype, dims, metrics);
        }
        return Match.unmatched();
    }

    private static String stripSuffix(String uri, String suffix) {
        if (uri == null || suffix == null) {
            return "";
        }
        if (!endsWithInsensitive(uri, suffix)) {
            return uri;
        }
        return uri.substring(0, uri.length() - suffix.length());
    }

    /**
     * Returns the lowercased extension of the supplied file name (without the dot), or empty
     * string if the name has no extension or the dot is the first/last character. Mirrors the
     * download filter's {@code inferFileType} so the two filters can be queried with the same
     * shape of dashboard expression in ClickHouse.
     */
    private static String inferExtension(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return "";
        }
        int slash = fileName.lastIndexOf('/');
        String segment = slash < 0 ? fileName : fileName.substring(slash + 1);
        int dot = segment.lastIndexOf('.');
        if (dot <= 0 || dot == segment.length() - 1) {
            return "";
        }
        return segment.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static Double parseDoubleOrNull(String v) {
        if (v == null || v.isEmpty()) {
            return null;
        }
        try {
            return Double.parseDouble(v);
        } catch (NumberFormatException nfe) {
            return null;
        }
    }

    /** Match outcome carrier including extracted dimensions and metrics. */
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

        static Match of(String code, String subtype,
                Map<String, String> dims, Map<String, Double> metrics) {
            return new Match(true, code, subtype, dims, metrics);
        }
    }

    /** Compiled, immutable representation of one configured upload rule. */
    static final class UploadRule {
        final String name;
        final String subtype;
        final String urlSuffix;
        final String method;
        final List<Integer> exactStatuses;
        final boolean redirectBand;
        final boolean anyStatus;
        final boolean extractPathFromUrl;
        /** Form parameter name carrying the per-file file name; empty disables the extraction. */
        final String fileNameFormParam;
        /** paramName -> dimensionName (single-value strings). */
        final Map<String, String> queryParamDimensions;
        /** paramName -> metricName (single-value, parsed as double). */
        final Map<String, String> queryParamMetrics;
        /** paramName -> metricName (count of non-empty getParameterValues entries). */
        final Map<String, String> multiParamCountMetrics;
        /** paramName -> metricName (sum of numeric getParameterValues entries). */
        final Map<String, String> multiParamSumMetrics;
        /** Parameter names that must be present with a non-empty value for the rule to fire. */
        final List<String> requiredQueryParams;
        final int priority;
        int declarationOrder;

        UploadRule(String name, String subtype, String urlSuffix, String method,
                List<Integer> exactStatuses, boolean redirectBand, boolean anyStatus,
                boolean extractPathFromUrl, String fileNameFormParam,
                Map<String, String> queryParamDimensions,
                Map<String, String> queryParamMetrics,
                Map<String, String> multiParamCountMetrics,
                Map<String, String> multiParamSumMetrics,
                List<String> requiredQueryParams, int priority) {
            this.name = name;
            this.subtype = subtype;
            this.urlSuffix = urlSuffix;
            this.method = method;
            this.exactStatuses = exactStatuses;
            this.redirectBand = redirectBand;
            this.anyStatus = anyStatus;
            this.extractPathFromUrl = extractPathFromUrl;
            this.fileNameFormParam = fileNameFormParam;
            this.queryParamDimensions = queryParamDimensions;
            this.queryParamMetrics = queryParamMetrics;
            this.multiParamCountMetrics = multiParamCountMetrics;
            this.multiParamSumMetrics = multiParamSumMetrics;
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

    static UploadRule parseRule(String raw) {
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
        String urlSuffix = required(kv, "url_suffix");
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

        boolean extractPathFromUrl = parseBool(kv.get("extract_path_from_url"), false);
        String fileNameFormParam = kv.getOrDefault("file_name_form_param", "");
        Map<String, String> queryParamDimensions = parseMappingPairs(kv.get("query_param_dimensions"));
        Map<String, String> queryParamMetrics = parseMappingPairs(kv.get("query_param_metrics"));
        Map<String, String> multiParamCountMetrics = parseMappingPairs(kv.get("multi_param_count_metrics"));
        Map<String, String> multiParamSumMetrics = parseMappingPairs(kv.get("multi_param_sum_metrics"));
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

        return new UploadRule(name, subtype, urlSuffix, method,
                Collections.unmodifiableList(exact), band, anyStatus,
                extractPathFromUrl, fileNameFormParam,
                Collections.unmodifiableMap(queryParamDimensions),
                Collections.unmodifiableMap(queryParamMetrics),
                Collections.unmodifiableMap(multiParamCountMetrics),
                Collections.unmodifiableMap(multiParamSumMetrics),
                Collections.unmodifiableList(requiredQueryParams),
                priority);
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
            "name", "subtype", "url_suffix", "method", "status",
            "extract_path_from_url",
            "file_name_form_param",
            "query_param_dimensions", "query_param_metrics",
            "multi_param_count_metrics", "multi_param_sum_metrics",
            "query_params_required",
            "priority"));

    private static void validateKnownKeys(Set<String> keys) {
        for (String k : keys) {
            if (!KNOWN_KEYS.contains(k)) {
                throw new IllegalArgumentException("unknown key '" + k + "' (allowed: " + KNOWN_KEYS + ")");
            }
        }
    }

    /**
     * Strictly non-invasive response wrapper. Mirrors
     * {@link DownloadTrackingFilter.ObservationResponse}: overrides only the methods that set the
     * terminal HTTP status so we can observe it after the chain returns. Crucially this class
     * does <strong>not</strong> override {@code getOutputStream()} or {@code getWriter()} and
     * does not touch any response bytes — that is what makes it safe to sit in front of
     * AEMaaCS's own DBU servlets without breaking their JSON response payload.
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

    private static boolean allParamsHaveValue(HttpServletRequest request, List<String> names) {
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
