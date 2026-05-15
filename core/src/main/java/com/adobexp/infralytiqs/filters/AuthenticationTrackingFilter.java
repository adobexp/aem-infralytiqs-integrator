package com.adobexp.infralytiqs.filters;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;

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
import javax.servlet.http.Cookie;
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
 * Captures AEM login completions described by a fully-configurable list of {@link MatchRule}s.
 *
 * <p>Each rule is declared as a single string in the OSGi {@code patterns} array using a
 * tiny key/value DSL (see {@link #parseRule(String)}). Adding a new authentication-flow
 * fingerprint is therefore just an extra line in the config — no code changes, no redeploy.
 *
 * <p>The filter activates only while an OSGi configuration for {@value #PID} is present and
 * declares at least one valid rule; ingestion itself requires {@link InfralytiqsService}.
 *
 * <p><b>Why this is an OSGi HTTP Whiteboard filter and not a Sling filter:</b>
 * Sling's {@code FormAuthenticationHandler} intercepts {@code j_security_check} requests inside
 * {@code SlingAuthenticator.handleSecurity()}, writes the response (status + {@code login-token}
 * cookie) and returns {@code false} so the Sling main servlet exits before invoking the Sling
 * filter chain. A {@code sling.filter.scope=REQUEST} filter therefore never observes those
 * requests. The HTTP Whiteboard layer sits between the Felix HTTP service and the Sling main
 * servlet, so this filter both (a) is invoked before Sling auth runs, and (b) wraps the response
 * in time to observe the {@code login-token} cookie written by the auth handler.
 */
@Component(
        service = Filter.class,
        immediate = false,
        configurationPid = AuthenticationTrackingFilter.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {
                // OSGi HTTP Whiteboard expects Servlet 3 path syntax (NOT regex). "/*" is the
                // canonical "all requests" pattern. Regex like "/.*" would be rejected as Invalid.
                "osgi.http.whiteboard.filter.pattern=/*",
                "osgi.http.whiteboard.filter.dispatcher=REQUEST",
                // The Sling main servlet that serves /content, /j_security_check, /libs, /apps
                // is registered to the named whiteboard context "org.apache.sling" — NOT to the
                // unnamed "default" context. Without this selector our filter would land in the
                // default context (which contains no servlets reachable via normal AEM URLs) and
                // would never be invoked.
                "osgi.http.whiteboard.context.select=(osgi.http.whiteboard.context.name=org.apache.sling)",
                "service.ranking:Integer=10000"
        })
@Designate(ocd = AuthenticationTrackingFilter.AuthFilterCfg.class)
public final class AuthenticationTrackingFilter implements Filter {

    static final String PID = "com.adobexp.infralytiqs.filters.AuthenticationTrackingFilter";

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationTrackingFilter.class);

    private static final String DEFAULT_LOGIN_COOKIE = "login-token";

    /** Verbatim defaults reproducing the original Pattern 1 / 2 / 3. */
    private static final String[] DEFAULT_PATTERNS = {
            "name=pattern_1_saml_login;subtype=post_saml_response_redirect_status_302"
                    + ";url_suffix=/saml_login;method=POST;status=redirect;response_cookie=login-token"
                    + ";body_contains=SAMLResponse=;priority=1",
            "name=pattern_2_oidc_fragment;subtype=get_oauth_exchange_redirect_status_302"
                    + ";url_suffix=/j_security_check;method=GET;status=redirect;response_cookie=login-token"
                    + ";query_params=code;priority=2",
            "name=pattern_3_basic_form;subtype=post_basic_credentials_status_200"
                    + ";url_suffix=/j_security_check;method=POST;status=200;response_cookie=login-token"
                    + ";form_params=j_username,j_password;priority=3"
    };

    @ObjectClassDefinition(
            name = "Infralytiqs Authentication Tracking Filter",
            description = "Felix activates the sling filter once this configuration PID is present "
                    + "and declares at least one valid pattern.")
    public @interface AuthFilterCfg {

        @AttributeDefinition(
                name = "Comment",
                description = "Optional textual hint for admins — unused at runtime.")
        String marker() default "";

        @AttributeDefinition(
                name = "Authentication tracking patterns",
                description =
                        "One pattern per entry, written as 'key=value;key=value;...'. "
                                + "Recognised keys: name (required, used as auth_tracking_pattern), "
                                + "subtype (required, used as event_subtype), "
                                + "event_type (optional, defaults to 'authentication_success'; set to 'logout' for "
                                + "logout-style endpoints so events route to a distinct ClickHouse event_type), "
                                + "url_suffix (required, case-insensitive ends-with), "
                                + "method (required, e.g. POST or GET), "
                                + "status (required, either a number, a comma-separated list, or 'redirect'), "
                                + "response_cookie (default 'login-token'), "
                                + "query_params (comma-separated list — all must have a non-empty value), "
                                + "form_params (comma-separated list — all must have a non-empty value; triggers body buffering on POST), "
                                + "body_contains (substring that must appear in the buffered POST body), "
                                + "priority (integer, lower checked first; defaults to declaration order).")
        String[] patterns() default {
                "name=pattern_1_saml_login;subtype=post_saml_response_redirect_status_302"
                        + ";url_suffix=/saml_login;method=POST;status=redirect;response_cookie=login-token"
                        + ";body_contains=SAMLResponse=;priority=1",
                "name=pattern_2_oidc_fragment;subtype=get_oauth_exchange_redirect_status_302"
                        + ";url_suffix=/j_security_check;method=GET;status=redirect;response_cookie=login-token"
                        + ";query_params=code;priority=2",
                "name=pattern_3_basic_form;subtype=post_basic_credentials_status_200"
                        + ";url_suffix=/j_security_check;method=POST;status=200;response_cookie=login-token"
                        + ";form_params=j_username,j_password;priority=3"
        };
    }

    /** Compiled snapshot of the declared rules. Volatile so {@link #doFilter} sees a coherent set. */
    private volatile List<MatchRule> rules = Collections.emptyList();

    /** Lower-cased cookie names that any active rule cares about; the response wrapper sniffs only these. */
    private volatile Set<String> watchedCookies = Collections.emptySet();

    /**
     * Lower-cased URL suffixes for which a POST body must be buffered (because at least one rule
     * for that suffix needs body or form-param introspection).
     */
    private volatile Set<String> bufferLanes = Collections.emptySet();

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile InfralytiqsService ingestPipeline;

    @Activate
    @Modified
    protected void activate(AuthFilterCfg cfg) {
        applyConfig(cfg);
    }

    private void applyConfig(AuthFilterCfg cfg) {
        String[] entries = cfg.patterns();
        if (entries == null || entries.length == 0) {
            entries = DEFAULT_PATTERNS;
        }

        List<MatchRule> compiled = new ArrayList<>(entries.length);
        for (int i = 0; i < entries.length; i++) {
            String raw = entries[i];
            if (raw == null || raw.trim().isEmpty()) {
                continue;
            }
            try {
                MatchRule rule = parseRule(raw);
                rule.declarationOrder = i;
                compiled.add(rule);
            } catch (IllegalArgumentException ex) {
                LOG.warn("[{}] ignoring invalid pattern entry #{} '{}': {}", PID, i, raw, ex.getMessage());
            }
        }

        compiled.sort((a, b) -> {
            int byPrio = Integer.compare(a.priority, b.priority);
            return byPrio != 0 ? byPrio : Integer.compare(a.declarationOrder, b.declarationOrder);
        });

        Set<String> cookies = new LinkedHashSet<>();
        Set<String> lanes = new LinkedHashSet<>();
        for (MatchRule r : compiled) {
            cookies.add(r.responseCookie.toLowerCase(Locale.ROOT));
            if (r.needsBodyBuffering()) {
                lanes.add(r.urlSuffix.toLowerCase(Locale.ROOT));
            }
        }

        this.rules = Collections.unmodifiableList(compiled);
        this.watchedCookies = Collections.unmodifiableSet(cookies);
        this.bufferLanes = Collections.unmodifiableSet(lanes);

        if (compiled.isEmpty()) {
            LOG.warn("[{}] no valid authentication tracking patterns configured — filter will match nothing", PID);
        } else {
            LOG.info("[{}] loaded {} authentication tracking pattern(s)", PID, compiled.size());
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

        List<MatchRule> activeRules = rules;
        Set<String> cookieSet = watchedCookies;

        if (activeRules.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // Fast pre-check: at the HTTP whiteboard layer we see *every* request (CSS, JS, images,
        // page renders, etc.). If no active rule could possibly match this request's
        // (urlSuffix, method) combination we skip the response wrapping and body buffering and
        // pass through with zero overhead beyond a few endsWith checks.
        String preMethod = Objects.toString(httpRequest.getMethod(), "GET");
        String preUri = Objects.toString(httpRequest.getRequestURI(), "");
        boolean anyRuleCouldMatch = false;
        for (int i = 0; i < activeRules.size(); i++) {
            MatchRule candidate = activeRules.get(i);
            if (candidate.method.equalsIgnoreCase(preMethod)
                    && endsWithInsensitive(preUri, candidate.urlSuffix)) {
                anyRuleCouldMatch = true;
                break;
            }
        }
        if (!anyRuleCouldMatch) {
            chain.doFilter(request, response);
            return;
        }

        ObservationResponse mirrored = new ObservationResponse((HttpServletResponse) response, cookieSet);
        HttpServletRequest effective = bufferIfNeeded(httpRequest);

        chain.doFilter(effective, mirrored);

        Match verdict = matchAny(activeRules, effective, mirrored);
        if (!verdict.success) {
            return;
        }

        InfralytiqsService ingest = ingestPipeline;
        if (ingest == null) {
            LOG.warn("[{}] pattern {} recognised but ingestion service inactive", PID, verdict.code);
            return;
        }

        // Both `getRemoteUser` and `getUserPrincipal` are populated upstream by the AEM auth handler
        // that ran *before* us in the chain, so reading them here is a constant-time lookup on the
        // request — no JCR/UserManager calls happen on the request thread.
        String remoteUser = effective.getRemoteUser();
        if (isBlank(remoteUser) && effective.getUserPrincipal() != null) {
            remoteUser = effective.getUserPrincipal().getName();
        }

        InfralytiqsAnalyticsPayload payload = buildPayload(
                effective, verdict.code, verdict.subtype, verdict.eventType,
                mirrored.terminalStatus(), remoteUser);

        ingest.enqueue(payload);
        LOG.debug("[{}] dispatched {} analytics ({})", PID, verdict.eventType, verdict.code);
    }

    /**
     * Build the canonical authentication / logout payload from request/match context.
     * Shared with {@link AuthenticationCredentialsTracker} so payloads from either entry point
     * (HTTP whiteboard filter for SAML/OIDC; Sling auth post-processor for {@code /j_security_check})
     * land in ClickHouse with identical schemas.
     *
     * <p>The {@code eventType} parameter is the rule's declared event type (default
     * {@code authentication_success}; can be e.g. {@code logout}).
     */
    static InfralytiqsAnalyticsPayload buildPayload(HttpServletRequest request, String patternName,
            String subtype, String eventType, int httpStatus, String userIdHint) {
        String resolvedEventType = (eventType == null || eventType.isEmpty()) ? DEFAULT_EVENT_TYPE : eventType;
        return InfralytiqsAnalyticsPayload.builder(resolvedEventType)
                .eventSubtype(subtype)
                .pageUrl(canonical(request))
                .lookupPath(request.getRequestURI())
                .userIdHint(userIdHint)
                .dimension("auth_tracking_pattern", patternName)
                .dimension("http_method", request.getMethod())
                .dimension("http_status", Integer.toString(httpStatus))
                .dimension("request_uri", trim(request.getRequestURI(), 1024))
                .dimension("has_query_string", request.getQueryString() == null ? "false" : "true")
                .dimension("user_agent", trim(request.getHeader("User-Agent"), 512))
                .dimension("auth_domain", trim(domainOf(request), 256))
                .dimension("auth_origin", trim(originOf(request), 256))
                .metric("auth_signal", 1.0)
                .build();
    }

    private static Match matchAny(List<MatchRule> rules, HttpServletRequest request, ObservationResponse mirrored) {
        String method = Objects.toString(request.getMethod(), "GET");
        String path = Objects.toString(request.getRequestURI(), "");
        int status = mirrored.terminalStatus();

        for (MatchRule rule : rules) {
            if (!rule.method.equalsIgnoreCase(method)) {
                continue;
            }
            if (!endsWithInsensitive(path, rule.urlSuffix)) {
                continue;
            }
            if (!rule.statusMatches(status)) {
                continue;
            }
            if (!mirrored.cookieSeen(rule.responseCookie)) {
                continue;
            }
            if (!rule.queryParams.isEmpty() && !allParamsHaveValue(request, rule.queryParams)) {
                continue;
            }
            if (!rule.formParams.isEmpty() && !allParamsHaveValue(request, rule.formParams)) {
                continue;
            }
            if (!rule.bodyContains.isEmpty()) {
                if (!(request instanceof ReplayHttpServletRequest)) {
                    continue;
                }
                if (!((ReplayHttpServletRequest) request).cachedBodyContains(rule.bodyContains)) {
                    continue;
                }
            }
            return Match.of(rule.name, rule.subtype, rule.eventType);
        }
        return Match.unmatched();
    }

    static boolean allParamsHaveValue(HttpServletRequest request, List<String> names) {
        for (String name : names) {
            String v = request.getParameter(name);
            if (v == null || v.trim().isEmpty()) {
                return false;
            }
        }
        return true;
    }

    /** Wraps servlet response to correlate status cookies without affecting written bytes. */
    static final class ObservationResponse extends HttpServletResponseWrapper {

        private static final String HDR_SET_COOKIE = "Set-Cookie";

        private final Set<String> watchedCookieNamesLowercase;
        private final Set<String> seenCookieNamesLowercase = new LinkedHashSet<>();
        private int status = HttpServletResponse.SC_OK;

        ObservationResponse(HttpServletResponse delegate, Set<String> watchedCookieNamesLowercase) {
            super(delegate);
            this.watchedCookieNamesLowercase = watchedCookieNamesLowercase;
        }

        boolean cookieSeen(String name) {
            return name != null && seenCookieNamesLowercase.contains(name.toLowerCase(Locale.ROOT));
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
            seenCookieNamesLowercase.clear();
            status = HttpServletResponse.SC_OK;
            super.reset();
        }

        @Override
        public void addCookie(Cookie cookie) {
            sniffCookie(cookie);
            super.addCookie(cookie);
        }

        @Override
        public void addHeader(String name, String value) {
            sniffHeader(name, value);
            super.addHeader(name, value);
        }

        @Override
        public void setHeader(String name, String value) {
            sniffHeader(name, value);
            super.setHeader(name, value);
        }

        private void sniffCookie(Cookie cookie) {
            if (cookie == null) {
                return;
            }
            String lower = cookie.getName().toLowerCase(Locale.ROOT);
            if (watchedCookieNamesLowercase.contains(lower)) {
                seenCookieNamesLowercase.add(lower);
            }
        }

        private void sniffHeader(String header, String value) {
            if (header == null || value == null || !HDR_SET_COOKIE.equalsIgnoreCase(header)) {
                return;
            }
            String normalised = sanitiseCookieLine(value).toLowerCase(Locale.ROOT);
            for (String watched : watchedCookieNamesLowercase) {
                String needle = watched + "=";
                if (normalised.startsWith(needle)
                        || normalised.contains(";" + needle)
                        || normalised.contains("," + needle)) {
                    seenCookieNamesLowercase.add(watched);
                }
            }
        }

        /** Normalise separators so heuristic matching stays predictable. */
        private static String sanitiseCookieLine(String raw) {
            return raw.replace('\r', ';').replace('\n', ';').trim();
        }
    }

    /** Match outcome container. */
    private static final class Match {

        private static final Match NO_MATCH = new Match(false, "", "", "");

        final boolean success;
        final String code;
        final String subtype;
        final String eventType;

        private Match(boolean success, String patternCode, String subtypeLabel, String eventTypeLabel) {
            this.success = success;
            code = patternCode;
            subtype = subtypeLabel;
            eventType = eventTypeLabel;
        }

        static Match unmatched() {
            return NO_MATCH;
        }

        static Match of(String patternLabel, String subtypeLabel, String eventTypeLabel) {
            return new Match(true, patternLabel, subtypeLabel, eventTypeLabel);
        }
    }

    /** Default {@link InfralytiqsAnalyticsPayload#eventType()} emitted when a rule does not declare one. */
    static final String DEFAULT_EVENT_TYPE = "authentication_success";

    /** Compiled, immutable representation of one configured pattern. */
    static final class MatchRule {
        final String name;
        final String subtype;
        final String eventType;
        final String urlSuffix;
        final String method;
        final String responseCookie;
        final List<Integer> exactStatuses;
        final boolean redirectBand;
        final List<String> queryParams;
        final List<String> formParams;
        final String bodyContains;
        final int priority;
        int declarationOrder;

        MatchRule(String name, String subtype, String eventType, String urlSuffix, String method,
                String responseCookie, List<Integer> exactStatuses, boolean redirectBand,
                List<String> queryParams, List<String> formParams, String bodyContains, int priority) {
            this.name = name;
            this.subtype = subtype;
            this.eventType = eventType;
            this.urlSuffix = urlSuffix;
            this.method = method;
            this.responseCookie = responseCookie;
            this.exactStatuses = exactStatuses;
            this.redirectBand = redirectBand;
            this.queryParams = queryParams;
            this.formParams = formParams;
            this.bodyContains = bodyContains;
            this.priority = priority;
        }

        boolean statusMatches(int status) {
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

        boolean needsBodyBuffering() {
            return !bodyContains.isEmpty() || !formParams.isEmpty();
        }
    }

    /**
     * Parse a single pattern entry written as {@code key=value;key=value;...}. Whitespace around
     * keys/values is trimmed; unknown keys are rejected loudly so typos fail fast.
     */
    static MatchRule parseRule(String raw) {
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
        String eventType = kv.getOrDefault("event_type", DEFAULT_EVENT_TYPE);
        if (eventType.isEmpty()) {
            eventType = DEFAULT_EVENT_TYPE;
        }
        String urlSuffix = required(kv, "url_suffix");
        String method = required(kv, "method").toUpperCase(Locale.ROOT);
        String responseCookie = kv.getOrDefault("response_cookie", DEFAULT_LOGIN_COOKIE);
        if (responseCookie.isEmpty()) {
            responseCookie = DEFAULT_LOGIN_COOKIE;
        }

        String statusSpec = required(kv, "status");
        List<Integer> exact = new ArrayList<>();
        boolean band = false;
        for (String chunk : statusSpec.split(",")) {
            String c = chunk.trim();
            if (c.isEmpty()) {
                continue;
            }
            if ("redirect".equalsIgnoreCase(c)) {
                band = true;
                continue;
            }
            try {
                exact.add(Integer.parseInt(c));
            } catch (NumberFormatException nfe) {
                throw new IllegalArgumentException("status token '" + c + "' is not an integer or 'redirect'");
            }
        }
        if (!band && exact.isEmpty()) {
            throw new IllegalArgumentException("status must specify at least one numeric code or 'redirect'");
        }

        List<String> queryParams = csv(kv.get("query_params"));
        List<String> formParams = csv(kv.get("form_params"));
        String bodyContains = kv.getOrDefault("body_contains", "");

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

        return new MatchRule(name, subtype, eventType, urlSuffix, method, responseCookie,
                Collections.unmodifiableList(exact), band,
                Collections.unmodifiableList(queryParams),
                Collections.unmodifiableList(formParams),
                bodyContains, priority);
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
            "name", "subtype", "event_type", "url_suffix", "method", "status",
            "response_cookie", "query_params", "form_params", "body_contains", "priority"));

    private static void validateKnownKeys(Set<String> keys) {
        for (String k : keys) {
            if (!KNOWN_KEYS.contains(k)) {
                throw new IllegalArgumentException("unknown key '" + k + "' (allowed: " + KNOWN_KEYS + ")");
            }
        }
    }

    private HttpServletRequest bufferIfNeeded(HttpServletRequest request) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return request;
        }
        Set<String> lanes = bufferLanes;
        if (lanes.isEmpty()) {
            return request;
        }

        String ct = Objects.toString(request.getContentType(), "");
        if (!Ct.isLikelyUrlForm(ct) || Ct.isMultipart(ct)) {
            return request;
        }

        String requestUri = request.getRequestURI();
        boolean inLane = false;
        for (String suffix : lanes) {
            if (endsWithInsensitive(requestUri, suffix)) {
                inLane = true;
                break;
            }
        }
        if (!inLane) {
            return request;
        }

        Charset charset = CharsetHelper.resolveCharset(request.getCharacterEncoding());
        return ReplayHttpServletRequest.buffer(request, charset);
    }

    /** Detects multipart vs urlencoded payloads. */
    private static final class Ct {
        private Ct() {}

        static boolean isLikelyUrlForm(String header) {
            if (header == null || header.isBlank()) {
                /** Native login historically omits CT but body still url-encoded. */
                return true;
            }
            String lower = header.toLowerCase(Locale.ROOT);
            return lower.startsWith("application/x-www-form-urlencoded");
        }

        static boolean isMultipart(String header) {
            return header != null && header.toLowerCase(Locale.ROOT).startsWith("multipart/");
        }
    }

    private static final class CharsetHelper {
        private CharsetHelper() {}

        static Charset resolveCharset(String characterEncoding) {
            if (characterEncoding == null || characterEncoding.isBlank()) {
                return StandardCharsets.UTF_8;
            }
            try {
                return Charset.forName(characterEncoding);
            } catch (Exception unsupported) {
                return StandardCharsets.UTF_8;
            }
        }
    }

    /** Request wrapper buffering POST bodies for matchers. */
    private static final class ReplayHttpServletRequest extends HttpServletRequestWrapper {

        final byte[] cache;
        final Charset charset;
        final Map<String, String[]> parameterUnion;

        private ReplayHttpServletRequest(HttpServletRequest delegate, byte[] body, Charset encoding,
                Map<String, String[]> params) {
            super(delegate);
            cache = Arrays.copyOf(body, body.length);
            charset = encoding;
            parameterUnion = params;
        }

        static ReplayHttpServletRequest buffer(HttpServletRequest downstream, Charset encoding) throws IOException {
            InputStream inbound = downstream.getInputStream();
            byte[] payload = inbound.readAllBytes();
            LinkedHashMap<String, String[]> formVals = Forms.decode(payload, encoding);
            LinkedHashMap<String, String[]> queryVals = Forms.decodeQuery(downstream.getQueryString(), encoding);
            LinkedHashMap<String, String[]> union = Forms.mergePreferBody(formVals, queryVals);
            return new ReplayHttpServletRequest(downstream, payload, encoding, union);
        }

        boolean cachedBodyContains(String substring) {
            return new String(cache, charset).contains(substring);
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream stream = new ByteArrayInputStream(cache);
            return new ServletInputStream() {
                @Override
                public int read() throws IOException {
                    return stream.read();
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
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }

        @Override
        public String getParameter(String name) {
            String[] values = parameterUnion.get(name);
            return values == null || values.length == 0 ? null : values[0];
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return Collections.unmodifiableMap(parameterUnion);
        }

        @Override
        public java.util.Enumeration<String> getParameterNames() {
            return Collections.enumeration(parameterUnion.keySet());
        }

        @Override
        public String[] getParameterValues(String name) {
            String[] vals = parameterUnion.get(name);
            return vals == null ? null : Arrays.copyOf(vals, vals.length);
        }
    }

    /** Form parsing helpers. */
    private static final class Forms {
        private Forms() {}

        static LinkedHashMap<String, String[]> decode(byte[] payload, Charset charset) {
            if (payload.length == 0) {
                return new LinkedHashMap<>();
            }
            return decodeQuery(new String(payload, charset), charset);
        }

        static LinkedHashMap<String, String[]> decodeQuery(String query, Charset charset) {
            LinkedHashMap<String, String[]> accumulator = new LinkedHashMap<>();
            if (query == null || query.isBlank()) {
                return accumulator;
            }
            for (String token : query.split("&")) {
                if (token.isEmpty()) {
                    continue;
                }
                int splitter = token.indexOf('=');
                String key = decodeComponent(splitter > 0 ? token.substring(0, splitter) : token, charset);
                String value =
                        splitter >= 0 && splitter + 1 < token.length()
                                ? decodeComponent(token.substring(splitter + 1), charset)
                                : "";
                append(accumulator, key, value);
            }
            return accumulator;
        }

        static LinkedHashMap<String, String[]> mergePreferBody(LinkedHashMap<String, String[]> bodyVals,
                LinkedHashMap<String, String[]> queryVals) {
            LinkedHashMap<String, String[]> unified = new LinkedHashMap<>();
            unified.putAll(queryVals);
            bodyVals.forEach((k, v) -> unified.put(k, Arrays.copyOf(v, v.length)));
            return unified;
        }

        private static void append(LinkedHashMap<String, String[]> target, String key, String value) {
            target.compute(
                    key,
                    (ignored, prev) -> {
                        if (prev == null || prev.length == 0) {
                            return new String[] {value};
                        }
                        String[] grown = Arrays.copyOf(prev, prev.length + 1);
                        grown[prev.length] = value;
                        return grown;
                    });
        }

        private static String decodeComponent(String raw, Charset charset) {
            return java.net.URLDecoder.decode(raw.replace('+', ' '), charset);
        }
    }

    static boolean endsWithInsensitive(String path, String needle) {
        if (path == null || needle == null || needle.length() > path.length()) {
            return false;
        }
        return path.regionMatches(true, path.length() - needle.length(), needle, 0, needle.length());
    }

    static String trim(String candidate, int max) {
        if (candidate == null) {
            return "";
        }
        return candidate.length() <= max ? candidate : candidate.substring(0, max);
    }

    static String canonical(HttpServletRequest request) {
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

    /**
     * Resolves the public-facing domain the user authenticated against. Reads only request-scoped
     * headers/properties — strictly O(1) on the request thread, no JCR or network calls.
     * Honours {@code X-Forwarded-Host} when present (first hop wins) so reverse-proxied sites still
     * report their public hostname rather than the internal AEM one.
     */
    static String domainOf(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-Host");
        if (filled(forwarded)) {
            int comma = forwarded.indexOf(',');
            String first = comma > 0 ? forwarded.substring(0, comma).trim() : forwarded.trim();
            return stripPort(first);
        }
        String host = request.getHeader("Host");
        if (filled(host)) {
            return stripPort(host.trim());
        }
        return fallback(request.getServerName(), "");
    }

    /**
     * Returns the full {@code scheme://host:port} the user authenticated against. Like
     * {@link #domainOf(HttpServletRequest)} this is purely request-scoped and runs in O(1) on the
     * request thread. Honours {@code X-Forwarded-Proto} / {@code X-Forwarded-Port} so reverse-proxied
     * sites report their public origin rather than the internal AEM listener.
     */
    static String originOf(HttpServletRequest request) {
        String scheme = request.getHeader("X-Forwarded-Proto");
        if (!filled(scheme)) {
            scheme = fallback(request.getScheme(), "http");
        }
        int firstComma = scheme.indexOf(',');
        if (firstComma > 0) {
            scheme = scheme.substring(0, firstComma).trim();
        }

        String host;
        Integer port = null;
        String forwardedHost = request.getHeader("X-Forwarded-Host");
        if (filled(forwardedHost)) {
            int comma = forwardedHost.indexOf(',');
            String first = comma > 0 ? forwardedHost.substring(0, comma).trim() : forwardedHost.trim();
            host = stripPort(first);
            String hostPortPart = portOf(first);
            if (hostPortPart != null) {
                port = parsePortOrNull(hostPortPart);
            }
            String forwardedPort = request.getHeader("X-Forwarded-Port");
            if (filled(forwardedPort)) {
                int pComma = forwardedPort.indexOf(',');
                String firstPort = pComma > 0 ? forwardedPort.substring(0, pComma).trim() : forwardedPort.trim();
                Integer parsed = parsePortOrNull(firstPort);
                if (parsed != null) {
                    port = parsed;
                }
            }
        } else {
            String hostHeader = request.getHeader("Host");
            if (filled(hostHeader)) {
                host = stripPort(hostHeader.trim());
                port = parsePortOrNull(portOf(hostHeader.trim()));
            } else {
                host = fallback(request.getServerName(), "");
            }
            if (port == null) {
                int sp = request.getServerPort();
                if (sp > 0) {
                    port = sp;
                }
            }
        }

        if (host == null || host.isEmpty()) {
            return "";
        }
        if (port == null || isDefaultPort(scheme, port)) {
            return scheme + "://" + host;
        }
        // IPv6 literal hosts must be re-bracketed in the URL form.
        boolean ipv6 = host.indexOf(':') >= 0;
        return scheme + "://" + (ipv6 ? "[" + host + "]" : host) + ":" + port;
    }

    private static boolean isDefaultPort(String scheme, int port) {
        return ("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443);
    }

    private static Integer parsePortOrNull(String portString) {
        if (portString == null || portString.isEmpty()) {
            return null;
        }
        try {
            int p = Integer.parseInt(portString.trim());
            return p > 0 ? p : null;
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    /** Returns the port portion of a {@code host[:port]} string, or {@code null} if absent. */
    private static String portOf(String hostHeader) {
        if (hostHeader == null || hostHeader.isEmpty()) {
            return null;
        }
        if (hostHeader.startsWith("[")) {
            int closing = hostHeader.indexOf(']');
            if (closing > 0 && closing + 1 < hostHeader.length() && hostHeader.charAt(closing + 1) == ':') {
                return hostHeader.substring(closing + 2);
            }
            return null;
        }
        int colon = hostHeader.indexOf(':');
        return colon > 0 && colon + 1 < hostHeader.length() ? hostHeader.substring(colon + 1) : null;
    }

    private static String stripPort(String hostHeader) {
        if (hostHeader == null || hostHeader.isEmpty()) {
            return "";
        }
        // IPv6 literal: [::1]:8080
        if (hostHeader.startsWith("[")) {
            int closing = hostHeader.indexOf(']');
            return closing > 0 ? hostHeader.substring(1, closing) : hostHeader;
        }
        int colon = hostHeader.indexOf(':');
        return colon > 0 ? hostHeader.substring(0, colon) : hostHeader;
    }

}
