package com.adobexp.infralytiqs.filters;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
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
 * Captures asset download completions described by a fully-configurable list of {@link DownloadRule}s
 * and dispatches the event asynchronously through {@link InfralytiqsService}.
 *
 * <p>The filter wraps the response with a tee'd output stream <em>only</em> when at least one
 * candidate rule for the current URL+method requires JSON body inspection — so requests that aren't
 * downloads pay zero buffering cost. All HTTP I/O on the request thread is bounded by:
 * (a) the cheap URL-suffix lookup, (b) the capped {@code responseBufferMaxBytes} byte copy of the
 * response (default 256 KB), and (c) a single non-blocking enqueue. No JCR work, no synchronous
 * outbound calls — the service handles batching, user-profile enrichment and HTTP shipping on its
 * own worker pool.
 *
 * <p>This component is declared with {@link ConfigurationPolicy#REQUIRE} and {@link #PID}.
 * Declarative Services therefore does not register the {@link Filter} service (and this filter
 * does not run) until Configuration Admin has an entry for that PID — for example
 * {@code com.adobexp.infralytiqs.filters.DownloadTrackingFilter} in the Felix console or a
 * matching {@code cfg.json} in the deployment package. Ingestion still requires
 * {@link InfralytiqsService} at runtime.
 *
 * <h2>Registration: OSGi HTTP Whiteboard, not Sling filter</h2>
 *
 * <p>On AEMaaCS the asset download endpoints — {@code *.downloadbinaries.json} on author and
 * {@code *.download-asset-renditions.zip} on publish — are served by handlers that do not
 * reliably traverse the Sling main-servlet filter chain (the same reason
 * {@link AuthenticationTrackingFilter} cannot rely on {@code sling.filter.scope=REQUEST} for
 * {@code /j_security_check} — Adobe's auth/asset handlers can short-circuit the response back to
 * the Felix HTTP layer before Sling filters fire). Registering this component as an OSGi HTTP
 * Whiteboard filter scoped to the {@code org.apache.sling} HTTP context places it between the
 * Felix HTTP service and the Sling main servlet, so it is invoked for <em>every</em> request that
 * reaches AEM and observes the response after the entire downstream chain has written it.
 *
 * <p>The {@code osgi.http.whiteboard.context.select} selector is mandatory: the Sling main servlet
 * (which serves {@code /content}, {@code /libs}, {@code /apps}, asset binaries, etc.) is registered
 * to the named whiteboard context {@code org.apache.sling}, NOT to the unnamed default context. A
 * filter registered without this selector lands in the default context and is never invoked for
 * AEM URLs.
 */
@Component(
        service = Filter.class,
        immediate = false,
        configurationPid = DownloadTrackingFilter.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {
                // OSGi HTTP Whiteboard expects Servlet 3 path syntax (NOT regex). "/*" is the
                // canonical "all requests" pattern. Regex like "/.*" would be rejected as Invalid.
                "osgi.http.whiteboard.filter.pattern=/*",
                "osgi.http.whiteboard.filter.dispatcher=REQUEST",
                // Bind to the named whiteboard context that hosts AEM's Sling main servlet. Without
                // this selector our filter lands in the default (empty) context and is never invoked.
                "osgi.http.whiteboard.context.select=(osgi.http.whiteboard.context.name=org.apache.sling)",
                // Sit just behind AuthenticationTrackingFilter (10000) so the user is already
                // resolved on the request thread by the time we observe the download response.
                "service.ranking:Integer=9000"
        })
@Designate(ocd = DownloadTrackingFilter.DownloadFilterCfg.class)
public final class DownloadTrackingFilter implements Filter {

    static final String PID = "com.adobexp.infralytiqs.filters.DownloadTrackingFilter";

    private static final Logger LOG = LoggerFactory.getLogger(DownloadTrackingFilter.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @ObjectClassDefinition(
            name = "Infralytiqs Download Tracking Filter",
            description = "Felix activates this sling filter once a configuration PID is present "
                    + "and declares at least one valid download pattern.")
    public @interface DownloadFilterCfg {

        @AttributeDefinition(
                name = "Comment",
                description = "Optional textual hint for admins — unused at runtime.")
        String marker() default "";

        @AttributeDefinition(
                name = "Download tracking patterns",
                description =
                        "One pattern per entry, written as 'key=value;key=value;...'. "
                                + "Recognised keys: name (required, used as download_tracking_pattern), "
                                + "subtype (required, used as event_subtype), "
                                + "url_suffix (required, case-insensitive ends-with), "
                                + "method (required, POST or GET), "
                                + "status (required: numeric code, comma-list, 'redirect', or 'any'), "
                                + "response_is_json (default false, set true to capture+parse the response body), "
                                + "json_required_props (comma-list of JSON property names that must be present and non-null), "
                                + "extract_path_from_url (default false, when true the request URI minus the suffix is emitted as 'download_path'), "
                                + "json_string_props (comma-list of jsonProp:dimensionName mappings — extracts string values), "
                                + "json_array_props (comma-list of jsonProp:dimensionName mappings — extracts arrays of strings), "
                                + "query_param_dimensions (comma-list of queryParam:dimensionName mappings — extracts request query string values into dimensions; useful for endpoints whose payload is binary so JSON inspection is unavailable), "
                                + "query_params_required (comma-list of query parameter names that must be present and non-empty for the rule to fire), "
                                + "priority (integer, lower checked first; defaults to declaration order).")
        String[] patterns() default {
                "name=pattern_1_downloadbinaries_init;subtype=post_downloadbinaries_init_status_201"
                        + ";url_suffix=.downloadbinaries.json;method=POST;status=201"
                        + ";response_is_json=true;json_required_props=downloadId"
                        + ";extract_path_from_url=true;json_string_props=downloadId:download_id;priority=1",
                "name=pattern_2_renditions_zip;subtype=post_download_asset_renditions_zip_status_200"
                        + ";url_suffix=download-asset-renditions.zip;method=POST;status=200"
                        + ";response_is_json=true;json_required_props=id,assets,archiveName"
                        + ";json_string_props=id:download_id,archiveName:download_archive_name"
                        + ";json_array_props=assets:download_paths;priority=2",
                "name=pattern_3_download_bin;subtype=get_download_bin_status_200"
                        + ";url_suffix=.download.bin;method=GET;status=200"
                        + ";extract_path_from_url=true;priority=3",
                "name=pattern_4_downloadbinaries_fetch;subtype=get_downloadbinaries_fetch_status_200"
                        + ";url_suffix=.downloadbinaries.json;method=GET;status=200"
                        + ";query_params_required=downloadId,artifactId"
                        + ";query_param_dimensions=downloadId:download_id,artifactId:download_artifact_id;priority=4"
        };

        @AttributeDefinition(
                name = "Response buffer max bytes",
                description = "Hard cap on the in-memory response copy used for JSON parsing. "
                        + "If a response exceeds this size while a JSON-asserting rule is active, "
                        + "the rule will not match (we won't ship a truncated payload).")
        int responseBufferMaxBytes() default 262144;
    }

    private volatile List<DownloadRule> rules = Collections.emptyList();
    private volatile int responseBufferMaxBytes = 262144;

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile InfralytiqsService ingestPipeline;

    @Activate
    @Modified
    protected void activate(DownloadFilterCfg cfg) {
        applyConfig(cfg);
    }

    private void applyConfig(DownloadFilterCfg cfg) {
        String[] entries = cfg.patterns();
        List<DownloadRule> compiled = new ArrayList<>(entries == null ? 0 : entries.length);

        if (entries != null) {
            for (int i = 0; i < entries.length; i++) {
                String raw = entries[i];
                if (raw == null || raw.trim().isEmpty()) {
                    continue;
                }
                try {
                    DownloadRule rule = parseRule(raw);
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
        this.responseBufferMaxBytes = Math.max(4096, cfg.responseBufferMaxBytes());

        if (compiled.isEmpty()) {
            LOG.warn("[{}] no valid download tracking patterns configured — filter will match nothing", PID);
        } else {
            LOG.info("[{}] loaded {} download tracking pattern(s); response buffer cap = {} bytes",
                    PID, compiled.size(), this.responseBufferMaxBytes);
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

        List<DownloadRule> activeRules = rules;
        if (activeRules.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Pre-filter rules by URL+method on the request thread BEFORE wrapping the response, so that
        // requests outside any download lane keep flowing through the original (unwrapped) response.
        List<DownloadRule> candidates = preMatch(activeRules, httpRequest);
        if (candidates.isEmpty()) {
            chain.doFilter(httpRequest, httpResponse);
            return;
        }

        boolean needsBody = false;
        for (DownloadRule r : candidates) {
            if (r.responseIsJson) {
                needsBody = true;
                break;
            }
        }

        ObservationResponseWrapper mirrored =
                new ObservationResponseWrapper(httpResponse, needsBody, responseBufferMaxBytes);

        chain.doFilter(httpRequest, mirrored);

        Match verdict = matchAny(candidates, httpRequest, mirrored);
        if (!verdict.success) {
            return;
        }

        InfralytiqsService ingest = ingestPipeline;
        if (ingest == null) {
            LOG.warn("[{}] pattern {} recognised but ingestion service inactive", PID, verdict.code);
            return;
        }

        // Both `getRemoteUser` and `getUserPrincipal` are populated upstream by the AEM auth
        // handler that ran *before* us in the chain — constant-time read on the request thread.
        // The service performs JCR profile enrichment (email + display name) asynchronously.
        String remoteUser = httpRequest.getRemoteUser();
        if (isBlank(remoteUser) && httpRequest.getUserPrincipal() != null) {
            remoteUser = httpRequest.getUserPrincipal().getName();
        }

        InfralytiqsAnalyticsPayload.Builder b =
                InfralytiqsAnalyticsPayload.builder("asset_download")
                        .eventSubtype(verdict.subtype)
                        .pageUrl(canonical(httpRequest))
                        .lookupPath(httpRequest.getRequestURI())
                        .userIdHint(remoteUser)
                        .dimension("download_tracking_pattern", verdict.code)
                        .dimension("http_method", httpRequest.getMethod())
                        .dimension("http_status", Integer.toString(mirrored.terminalStatus()))
                        .dimension("request_uri", trim(httpRequest.getRequestURI(), 1024))
                        .dimension("user_agent", trim(httpRequest.getHeader("User-Agent"), 512))
                        .metric("download_signal", 1.0);

        for (Map.Entry<String, String> e : verdict.extractedDimensions.entrySet()) {
            b.dimension(e.getKey(), e.getValue());
        }
        for (Map.Entry<String, Double> e : verdict.extractedMetrics.entrySet()) {
            b.metric(e.getKey(), e.getValue());
        }

        ingest.enqueue(b.build());
        LOG.debug("[{}] dispatched download analytics ({})", PID, verdict.code);
    }

    private static List<DownloadRule> preMatch(List<DownloadRule> all, HttpServletRequest request) {
        String method = Objects.toString(request.getMethod(), "GET");
        String uri = Objects.toString(request.getRequestURI(), "");
        List<DownloadRule> out = null;
        for (DownloadRule r : all) {
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

    private static Match matchAny(List<DownloadRule> candidates, HttpServletRequest request,
            ObservationResponseWrapper mirrored) {
        int status = mirrored.terminalStatus();
        for (DownloadRule rule : candidates) {
            if (!rule.statusMatches(status)) {
                continue;
            }
            if (!rule.requiredQueryParams.isEmpty()
                    && !allQueryParamsHaveValue(request, rule.requiredQueryParams)) {
                continue;
            }

            JsonNode root = null;
            if (rule.responseIsJson) {
                if (mirrored.bodyOverflowed()) {
                    LOG.debug("[{}] rule {} skipped — response body exceeded buffer cap", PID, rule.name);
                    continue;
                }
                root = parseCapturedJson(mirrored);
                if (root == null || !root.isObject()) {
                    continue;
                }
                if (!hasAllProps(root, rule.requiredJsonProps)) {
                    continue;
                }
            }

            Map<String, String> dims = new LinkedHashMap<>();
            Map<String, Double> metrics = new LinkedHashMap<>();

            if (rule.extractPathFromUrl) {
                String resourcePath = stripSuffix(request.getRequestURI(), rule.urlSuffix);
                if (!resourcePath.isEmpty()) {
                    dims.put("download_path", trim(resourcePath, 2048));
                    String fileType = inferFileType(resourcePath);
                    if (!fileType.isEmpty()) {
                        dims.put("download_file_type", fileType);
                    }
                    String fileName = lastSegment(resourcePath);
                    if (!fileName.isEmpty()) {
                        dims.put("download_file_name", trim(fileName, 512));
                    }
                }
            }

            for (Map.Entry<String, String> mapping : rule.queryParamDimensions.entrySet()) {
                String value = request.getParameter(mapping.getKey());
                if (value != null && !value.isEmpty()) {
                    dims.put(mapping.getValue(), trim(value, 1024));
                }
            }

            if (root != null) {
                for (Map.Entry<String, String> mapping : rule.jsonStringProps.entrySet()) {
                    JsonNode node = root.get(mapping.getKey());
                    if (node != null && node.isValueNode() && !node.isNull()) {
                        dims.put(mapping.getValue(), trim(node.asText(""), 1024));
                    }
                }
                for (Map.Entry<String, String> mapping : rule.jsonArrayProps.entrySet()) {
                    JsonNode node = root.get(mapping.getKey());
                    if (node != null && node.isArray()) {
                        List<String> values = new ArrayList<>(node.size());
                        for (JsonNode item : node) {
                            if (item != null && item.isValueNode() && !item.isNull()) {
                                values.add(item.asText(""));
                            }
                        }
                        dims.put(mapping.getValue(), trim(toJsonStringArray(values), 8192));
                        metrics.put(mapping.getValue() + "_count", (double) values.size());
                    }
                }
            }

            return Match.of(rule.name, rule.subtype, dims, metrics);
        }
        return Match.unmatched();
    }

    private static JsonNode parseCapturedJson(ObservationResponseWrapper mirrored) {
        byte[] body = mirrored.capturedBody();
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            return MAPPER.readTree(body);
        } catch (IOException ex) {
            LOG.debug("[{}] response body is not valid JSON ({} bytes): {}", PID, body.length, ex.toString());
            return null;
        }
    }

    private static boolean hasAllProps(JsonNode root, List<String> props) {
        for (String p : props) {
            JsonNode n = root.get(p);
            if (n == null || n.isNull()) {
                return false;
            }
        }
        return true;
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

    private static String inferFileType(String resourcePath) {
        if (resourcePath == null || resourcePath.isEmpty()) {
            return "";
        }
        int slash = resourcePath.lastIndexOf('/');
        String fileSegment = slash < 0 ? resourcePath : resourcePath.substring(slash + 1);
        int dot = fileSegment.lastIndexOf('.');
        if (dot <= 0 || dot == fileSegment.length() - 1) {
            return "";
        }
        return fileSegment.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static String lastSegment(String resourcePath) {
        if (resourcePath == null || resourcePath.isEmpty()) {
            return "";
        }
        int slash = resourcePath.lastIndexOf('/');
        return slash < 0 ? resourcePath : resourcePath.substring(slash + 1);
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

    /** Compiled, immutable representation of one configured download rule. */
    static final class DownloadRule {
        final String name;
        final String subtype;
        final String urlSuffix;
        final String method;
        final List<Integer> exactStatuses;
        final boolean redirectBand;
        final boolean anyStatus;
        final boolean responseIsJson;
        final List<String> requiredJsonProps;
        final boolean extractPathFromUrl;
        /** jsonPropName -> dimensionName */
        final Map<String, String> jsonStringProps;
        /** jsonPropName -> dimensionName */
        final Map<String, String> jsonArrayProps;
        /** queryParamName -> dimensionName (used when the response body cannot or shouldn't be parsed) */
        final Map<String, String> queryParamDimensions;
        /** Query parameter names that must be present with a non-empty value for the rule to fire. */
        final List<String> requiredQueryParams;
        final int priority;
        int declarationOrder;

        DownloadRule(String name, String subtype, String urlSuffix, String method,
                List<Integer> exactStatuses, boolean redirectBand, boolean anyStatus,
                boolean responseIsJson, List<String> requiredJsonProps,
                boolean extractPathFromUrl, Map<String, String> jsonStringProps,
                Map<String, String> jsonArrayProps,
                Map<String, String> queryParamDimensions, List<String> requiredQueryParams,
                int priority) {
            this.name = name;
            this.subtype = subtype;
            this.urlSuffix = urlSuffix;
            this.method = method;
            this.exactStatuses = exactStatuses;
            this.redirectBand = redirectBand;
            this.anyStatus = anyStatus;
            this.responseIsJson = responseIsJson;
            this.requiredJsonProps = requiredJsonProps;
            this.extractPathFromUrl = extractPathFromUrl;
            this.jsonStringProps = jsonStringProps;
            this.jsonArrayProps = jsonArrayProps;
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

    static DownloadRule parseRule(String raw) {
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

        boolean responseIsJson = parseBool(kv.get("response_is_json"), false);
        List<String> requiredJsonProps = csv(kv.get("json_required_props"));
        boolean extractPathFromUrl = parseBool(kv.get("extract_path_from_url"), false);
        Map<String, String> jsonStringProps = parseMappingPairs(kv.get("json_string_props"));
        Map<String, String> jsonArrayProps = parseMappingPairs(kv.get("json_array_props"));
        Map<String, String> queryParamDimensions = parseMappingPairs(kv.get("query_param_dimensions"));
        List<String> requiredQueryParams = csv(kv.get("query_params_required"));

        if (!requiredJsonProps.isEmpty() && !responseIsJson) {
            throw new IllegalArgumentException("json_required_props requires response_is_json=true");
        }
        if (!jsonStringProps.isEmpty() && !responseIsJson) {
            throw new IllegalArgumentException("json_string_props requires response_is_json=true");
        }
        if (!jsonArrayProps.isEmpty() && !responseIsJson) {
            throw new IllegalArgumentException("json_array_props requires response_is_json=true");
        }

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

        return new DownloadRule(name, subtype, urlSuffix, method,
                Collections.unmodifiableList(exact), band, anyStatus,
                responseIsJson, Collections.unmodifiableList(requiredJsonProps),
                extractPathFromUrl,
                Collections.unmodifiableMap(jsonStringProps),
                Collections.unmodifiableMap(jsonArrayProps),
                Collections.unmodifiableMap(queryParamDimensions),
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
                throw new IllegalArgumentException("invalid mapping entry '" + t + "' (expected jsonProp:dimensionName)");
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
            "response_is_json", "json_required_props",
            "extract_path_from_url", "json_string_props", "json_array_props",
            "query_param_dimensions", "query_params_required",
            "priority"));

    private static void validateKnownKeys(Set<String> keys) {
        for (String k : keys) {
            if (!KNOWN_KEYS.contains(k)) {
                throw new IllegalArgumentException("unknown key '" + k + "' (allowed: " + KNOWN_KEYS + ")");
            }
        }
    }

    /**
     * Wraps the response so the filter can: (a) observe terminal status,
     * (b) optionally tee the body bytes into a capped buffer for JSON parsing.
     * Body capture is disabled unless requested, so non-download requests pay zero overhead.
     */
    static final class ObservationResponseWrapper extends HttpServletResponseWrapper {

        private final boolean captureBody;
        private final int maxBytes;
        private final ByteArrayOutputStream buffer;
        private boolean overflowed;
        private int status = HttpServletResponse.SC_OK;
        private TeeServletOutputStream cachedStream;
        private PrintWriter cachedWriter;

        ObservationResponseWrapper(HttpServletResponse delegate, boolean captureBody, int maxBytes) {
            super(delegate);
            this.captureBody = captureBody;
            this.maxBytes = maxBytes;
            this.buffer = captureBody ? new ByteArrayOutputStream(Math.min(8192, maxBytes)) : null;
        }

        int terminalStatus() {
            return status;
        }

        boolean bodyOverflowed() {
            return overflowed;
        }

        byte[] capturedBody() {
            return buffer == null ? null : buffer.toByteArray();
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
            if (buffer != null) {
                buffer.reset();
                overflowed = false;
            }
            status = HttpServletResponse.SC_OK;
            super.reset();
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            if (!captureBody) {
                return super.getOutputStream();
            }
            if (cachedWriter != null) {
                throw new IllegalStateException("getWriter() already called on response");
            }
            if (cachedStream == null) {
                cachedStream = new TeeServletOutputStream(super.getOutputStream(), this);
            }
            return cachedStream;
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            if (!captureBody) {
                return super.getWriter();
            }
            if (cachedStream != null) {
                throw new IllegalStateException("getOutputStream() already called on response");
            }
            if (cachedWriter == null) {
                String enc = getCharacterEncoding();
                if (enc == null || enc.isEmpty()) {
                    enc = "UTF-8";
                }
                cachedStream = new TeeServletOutputStream(super.getOutputStream(), this);
                cachedWriter = new PrintWriter(new OutputStreamWriter(cachedStream, enc), false);
            }
            return cachedWriter;
        }

        @Override
        public void flushBuffer() throws IOException {
            if (cachedWriter != null) {
                cachedWriter.flush();
            }
            super.flushBuffer();
        }

        void recordBytes(byte[] b, int off, int len) {
            if (buffer == null) {
                return;
            }
            int remaining = maxBytes - buffer.size();
            if (remaining <= 0) {
                overflowed = true;
                return;
            }
            int copy = Math.min(remaining, len);
            buffer.write(b, off, copy);
            if (copy < len) {
                overflowed = true;
            }
        }

        void recordByte(int b) {
            if (buffer == null) {
                return;
            }
            if (buffer.size() >= maxBytes) {
                overflowed = true;
                return;
            }
            buffer.write(b);
        }
    }

    /** Tee'd output stream — every write is forwarded to the real client AND to the capped buffer. */
    static final class TeeServletOutputStream extends ServletOutputStream {

        private final ServletOutputStream delegate;
        private final ObservationResponseWrapper owner;

        TeeServletOutputStream(ServletOutputStream delegate, ObservationResponseWrapper owner) {
            this.delegate = delegate;
            this.owner = owner;
        }

        @Override
        public void write(int b) throws IOException {
            owner.recordByte(b);
            delegate.write(b);
        }

        @Override
        public void write(byte[] b) throws IOException {
            write(b, 0, b.length);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            owner.recordBytes(b, off, len);
            delegate.write(b, off, len);
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
