package com.adobexp.infralytiqs.service.impl;

import com.adobexp.infralytiqs.service.TenantService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

@Component(service = {TenantService.class})
@Designate(ocd = TenantServiceImpl.TenantConfig.class, factory = true)
public class TenantServiceImpl implements TenantService {

    static final String PID = "com.adobexp.infralytiqs.service.impl.TenantServiceImpl";

    private static final Logger LOG = LoggerFactory.getLogger(TenantServiceImpl.class);

    /** Relative path of the tenant-token endpoint on the analytics server. */
    private static final String TOKEN_PATH = "/il/token";

    /**
     * Clock-skew safety margin (ms) subtracted from the cached token's expiry
     * when deciding whether it is still usable, so we refresh slightly early
     * rather than handing out a token that expires mid-request.
     */
    private static final long EXPIRY_SKEW_MS = 30_000L;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Separator between the request-domain prefix and the bootstrap JS path
     * in each entry of {@link TenantConfig#infralytiqsClientBootstrapLibs()}.
     * Hard-coded to {@code ':'} so that paths beginning with {@code '/'}
     * (which is the only sensible value) can be split unambiguously — the
     * domain part is always the substring before the FIRST colon, which is
     * never part of a DNS host name.
     */
    private static final char DOMAIN_PATH_SEPARATOR = ':';

    private TenantConfig tenantConfig;

    /**
     * Pre-parsed view of {@link TenantConfig#infralytiqsClientBootstrapLibs()}
     * keyed by lowercase domain. Populated once at activation so the request
     * path stays allocation-free.
     */
    private Map<String, String> bootstrapLibByDomain = Collections.emptyMap();

    /** Guards the cached-token fields below. */
    private final Object tokenLock = new Object();

    /** The raw cached JWT last issued by {@code POST /il/token}. */
    private String cachedJwt;

    /** The {@code tokenId} claim parsed from {@link #cachedJwt}. */
    private String cachedTokenId;

    /** Epoch-millis expiry parsed from the cached JWT's {@code tokenExpiryTime} claim. */
    private long cachedExpiryEpochMs;

    /**
     * {@code true} only when companyId, clientKey AND clientSecret are all
     * configured. When {@code false}, the service still activates and all
     * non-credential methods keep working, but token-dependent operations are
     * disabled and emit WARN logs.
     */
    private volatile boolean credentialsConfigured;

    @Activate
    protected void activate(final TenantConfig tenantConfig) {
        this.tenantConfig = tenantConfig;
        this.bootstrapLibByDomain = parseBootstrapLibEntries(tenantConfig.infralytiqsClientBootstrapLibs());
        synchronized (tokenLock) {
            this.cachedJwt = null;
            this.cachedTokenId = null;
            this.cachedExpiryEpochMs = 0L;
        }
        // The service is ALWAYS initialised, even without credentials, so that
        // rootPath/tenantId/siteId/dbName/bootstrap-lib lookups keep working.
        // Token-dependent features are simply disabled until the credentials
        // are configured; surface that clearly with a single activation WARN.
        this.credentialsConfigured = !isBlank(tenantConfig.companyId())
                && !isBlank(tenantConfig.clientKey())
                && !isBlank(tenantConfig.clientSecret());
        if (!credentialsConfigured) {
            LOG.warn("Infralytiqs TenantService activated for tenant '{}' WITHOUT complete credentials "
                    + "(missing: {}). The service is initialised, but token-dependent operations "
                    + "(getToken/getCompanyId/getClientKey/getClientSecret) are disabled until "
                    + "companyId, clientKey and clientSecret are configured.",
                    safeTenant(), missingCredentialFields());
        }
    }

    /** @return {@code true} when {@code value} is null or blank after trimming. */
    private static boolean isBlank(final String value) {
        return value == null || value.trim().isEmpty();
    }

    /**
     * @return a human-readable, comma-separated list of the credential fields
     *         that are not configured (for diagnostics in WARN logs).
     */
    private String missingCredentialFields() {
        final StringBuilder sb = new StringBuilder();
        if (tenantConfig == null || isBlank(tenantConfig.companyId())) {
            sb.append("companyId");
        }
        if (tenantConfig == null || isBlank(tenantConfig.clientKey())) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("clientKey");
        }
        if (tenantConfig == null || isBlank(tenantConfig.clientSecret())) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("clientSecret");
        }
        return sb.length() == 0 ? "<none>" : sb.toString();
    }

    @Override
    public String getRootPath() {
        return tenantConfig.rootPath();
    }

    @Override
    public String getTenantId() {
        return tenantConfig.tenantId();
    }

    @Override
    public String getSiteId() {
        return tenantConfig.siteId();
    }

    @Override
    public String getDbName() {
        return tenantConfig.dbName();
    }

    @Override
    public String getAnalyticsServerUrl() {
        return tenantConfig.analyticsServerUrl();
    }

    @Override
    public String getCompanyId() {
        final String value = tenantConfig.companyId();
        if (isBlank(value)) {
            LOG.warn("Infralytiqs getCompanyId: companyId is not configured for tenant '{}'", safeTenant());
        }
        return value;
    }

    @Override
    public String getClientKey() {
        final String value = tenantConfig.clientKey();
        if (isBlank(value)) {
            LOG.warn("Infralytiqs getClientKey: clientKey is not configured for tenant '{}'", safeTenant());
        }
        return value;
    }

    @Override
    public String getClientSecret() {
        final String value = tenantConfig.clientSecret();
        if (isBlank(value)) {
            LOG.warn("Infralytiqs getClientSecret: clientSecret is not configured for tenant '{}'", safeTenant());
        }
        return value;
    }

    @Override
    public String getToken() {
        // Without complete credentials there is nothing to exchange for a token;
        // stay initialised, warn, and return empty rather than hitting the network.
        if (!credentialsConfigured) {
            LOG.warn("Infralytiqs getToken: cannot mint a token for tenant '{}' — missing credentials: {}",
                    safeTenant(), missingCredentialFields());
            return "";
        }

        // 1) Serve a still-valid cached tokenId without a network round-trip.
        synchronized (tokenLock) {
            if (cachedTokenId != null && isCachedTokenValid()) {
                return cachedTokenId;
            }
        }

        // 2) Cache empty or expired — fetch, verify, cache, and return.
        synchronized (tokenLock) {
            // Re-check inside the lock in case another thread just refreshed.
            if (cachedTokenId != null && isCachedTokenValid()) {
                return cachedTokenId;
            }
            try {
                final String jwt = fetchTokenJwt();
                if (jwt == null || jwt.isEmpty()) {
                    LOG.warn("Infralytiqs getToken: token endpoint returned no JWT for tenant '{}'", safeTenant());
                    return cachedTokenId != null ? cachedTokenId : "";
                }
                final JsonNode claims = verifyAndDecodeJwt(jwt, tenantConfig.clientSecret());
                final String tokenId = textClaim(claims, "tokenId");
                final long expiryMs = parseExpiry(claims);
                if (tokenId == null || tokenId.isEmpty()) {
                    LOG.warn("Infralytiqs getToken: JWT missing tokenId claim for tenant '{}'", safeTenant());
                    return "";
                }
                this.cachedJwt = jwt;
                this.cachedTokenId = tokenId;
                this.cachedExpiryEpochMs = expiryMs;
                return cachedTokenId;
            } catch (final Exception e) {
                LOG.error("Infralytiqs getToken: failed to obtain token for tenant '{}': {}", safeTenant(), e.toString());
                // Fall back to a stale token rather than nothing, if we have one.
                return cachedTokenId != null ? cachedTokenId : "";
            }
        }
    }

    /**
     * @return {@code true} when the cached JWT's expiry (minus a safety skew)
     *         is still in the future. Caller must hold {@link #tokenLock}.
     */
    private boolean isCachedTokenValid() {
        return cachedExpiryEpochMs > (System.currentTimeMillis() + EXPIRY_SKEW_MS);
    }

    /**
     * Calls {@code POST {analyticsServerUrl}/il/token} with the tenant
     * credential headers and returns the raw JWT string from the JSON
     * response ({@code data.token}), or {@code null} on any failure.
     */
    private String fetchTokenJwt() throws Exception {
        // Read config directly (not via the public getters) so this internal
        // path does not re-trigger the per-getter "not configured" WARN logs.
        final String base = tenantConfig.analyticsServerUrl();
        final String companyId = tenantConfig.companyId();
        final String clientKey = tenantConfig.clientKey();
        final String clientSecret = tenantConfig.clientSecret();
        final String tenantName = tenantConfig.tenantId();

        if (isBlank(base) || isBlank(companyId) || isBlank(clientKey) || isBlank(clientSecret)) {
            LOG.warn("Infralytiqs getToken: tenant credentials/analytics URL not fully configured for tenant '{}' (missing: {})",
                    safeTenant(), missingCredentialFields());
            return null;
        }

        final URI endpoint = stripTrailingSlash(URI.create(base.trim())).resolve(TOKEN_PATH);

        final HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        final HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(Duration.ofSeconds(20))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("companyId", companyId.trim())
                .header("tenantName", tenantName == null ? "" : tenantName.trim())
                .header("clientKey", clientKey.trim())
                .header("clientSecret", clientSecret.trim())
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        final HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            LOG.warn("Infralytiqs getToken: token endpoint returned HTTP {} for tenant '{}'",
                    response.statusCode(), safeTenant());
            return null;
        }

        final JsonNode root = MAPPER.readTree(response.body());
        final JsonNode data = root.path("data");
        final JsonNode tokenNode = data.path("token");
        return tokenNode.isMissingNode() || tokenNode.isNull() ? null : tokenNode.asText();
    }

    /**
     * Verifies an HS256 JWT against {@code secret} (the tenant clientSecret)
     * and returns its decoded payload as a {@link JsonNode}.
     *
     * @throws SecurityException if the token is malformed or the signature
     *         does not match.
     */
    private static JsonNode verifyAndDecodeJwt(final String jwt, final String secret) throws Exception {
        final String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new SecurityException("Malformed JWT (expected 3 segments)");
        }
        final String signingInput = parts[0] + "." + parts[1];
        final byte[] expectedSig = hmacSha256(signingInput.getBytes(StandardCharsets.UTF_8),
                secret.getBytes(StandardCharsets.UTF_8));
        final byte[] actualSig = Base64.getUrlDecoder().decode(parts[2]);
        if (!constantTimeEquals(expectedSig, actualSig)) {
            throw new SecurityException("JWT signature verification failed");
        }
        final byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        return MAPPER.readTree(new String(payload, StandardCharsets.UTF_8));
    }

    private static byte[] hmacSha256(final byte[] data, final byte[] key) throws Exception {
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static boolean constantTimeEquals(final byte[] a, final byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    private static String textClaim(final JsonNode claims, final String name) {
        final JsonNode n = claims.path(name);
        return n.isMissingNode() || n.isNull() ? null : n.asText();
    }

    /**
     * Resolves the cached-expiry epoch-millis from the JWT claims, preferring
     * the ISO-8601 {@code tokenExpiryTime} claim and falling back to the
     * standard numeric {@code exp} (seconds) claim.
     */
    private static long parseExpiry(final JsonNode claims) {
        final String iso = textClaim(claims, "tokenExpiryTime");
        if (iso != null && !iso.isEmpty()) {
            try {
                return Instant.parse(iso).toEpochMilli();
            } catch (final Exception ignored) {
                // fall through to exp
            }
        }
        final JsonNode exp = claims.path("exp");
        if (exp.isNumber()) {
            return exp.asLong() * 1000L;
        }
        return 0L;
    }

    private static URI stripTrailingSlash(final URI uri) {
        final String s = uri.toString();
        return s.endsWith("/") ? URI.create(s.substring(0, s.length() - 1)) : uri;
    }

    private String safeTenant() {
        try {
            return tenantConfig != null ? tenantConfig.tenantId() : "<none>";
        } catch (final Exception e) {
            return "<none>";
        }
    }

    @Override
    public String[] getInfralytiqsClientBootstrapLibs() {
        final String[] entries = tenantConfig.infralytiqsClientBootstrapLibs();
        return entries != null ? entries.clone() : new String[0];
    }

    @Override
    public String getClientBootstrapLibForDomain(final String domain) {
        if (domain == null || domain.isEmpty() || bootstrapLibByDomain.isEmpty()) {
            return "";
        }
        // Strip any :port if a caller accidentally passes a Host header
        // verbatim (e.g. "psassets.publicissapient.com:443"). DNS host names
        // never contain a colon, so the first ':' is always the port boundary.
        final int colon = domain.indexOf(DOMAIN_PATH_SEPARATOR);
        final String key = (colon > 0 ? domain.substring(0, colon) : domain)
                .trim()
                .toLowerCase(Locale.ROOT);
        final String lib = bootstrapLibByDomain.get(key);
        return lib != null ? lib : "";
    }

    /**
     * Parses the raw {@code "<host>:<path>"} configuration entries into a
     * lookup map keyed by lowercase domain. Malformed entries (no separator,
     * empty domain, empty path) are silently dropped — invalid OSGi config
     * values must never crash request rendering.
     */
    private static Map<String, String> parseBootstrapLibEntries(final String[] entries) {
        if (entries == null || entries.length == 0) {
            return Collections.emptyMap();
        }
        final Map<String, String> map = new LinkedHashMap<>(entries.length);
        for (final String raw : entries) {
            if (raw == null) {
                continue;
            }
            final String entry = raw.trim();
            if (entry.isEmpty()) {
                continue;
            }
            final int sep = entry.indexOf(DOMAIN_PATH_SEPARATOR);
            if (sep <= 0 || sep >= entry.length() - 1) {
                continue;
            }
            final String domain = entry.substring(0, sep).trim().toLowerCase(Locale.ROOT);
            final String path = entry.substring(sep + 1).trim();
            if (!domain.isEmpty() && !path.isEmpty()) {
                map.put(domain, path);
            }
        }
        return Collections.unmodifiableMap(map);
    }

    @ObjectClassDefinition(
            name = "Infralytiqs — tenant SDK bootstrap (factory)",
            description = "Per-site/rootPath tuple injected into HTL bootstrap for the browser SDK.")
    public @interface TenantConfig {

        @AttributeDefinition(name = "Root path of a tenant", type = AttributeType.STRING)
        String rootPath();

        @AttributeDefinition(name = "Infralytiqs Tenant ID", type = AttributeType.STRING)
        String tenantId();

        @AttributeDefinition(name = "Infralytiqs Site ID", type = AttributeType.STRING)
        String siteId();

        @AttributeDefinition(name = "ClickHouse DB Name", type = AttributeType.STRING)
        String dbName();

        @AttributeDefinition(name = "Analytics Server URL (st-ck-server)", type = AttributeType.STRING)
        String analyticsServerUrl();

        @AttributeDefinition(
                name = "Infralytiqs Company ID",
                description = "IL-Tenants.companyId that owns this tenant. Sent as the companyId "
                        + "header when exchanging tenant credentials for a JWT at POST /il/token.",
                type = AttributeType.STRING)
        String companyId();

        @AttributeDefinition(
                name = "Tenant Client Key",
                description = "IL-Tenants.clientKey for this tenant. Sent as the clientKey header "
                        + "to POST /il/token.",
                type = AttributeType.STRING)
        String clientKey();

        @AttributeDefinition(
                name = "Tenant Client Secret",
                description = "IL-Tenants.clientSecret for this tenant. Sent as the clientSecret "
                        + "header to POST /il/token and used as the HMAC key to verify/decode the "
                        + "returned JWT.",
                type = AttributeType.PASSWORD)
        String clientSecret();

        @AttributeDefinition(
                name = "Client Bootstrap Lib Mapping (domain:path)",
                description = "Multi-value list mapping a request host to the client-specific "
                        + "Infralytiqs bootstrap JS path. Each entry is of the form "
                        + "'<host>:<path>' (e.g. 'psassets.publicissapient.com:"
                        + "/cl/publicis/ps/infralytiqs-bootstrap.min.js'). The matching path "
                        + "is rendered as window.IL_CLIENT_BOOTSTRAP_LIB and the SDK auto-loads "
                        + "the script from its own CDN origin.",
                type = AttributeType.STRING,
                cardinality = Integer.MAX_VALUE)
        String[] infralytiqsClientBootstrapLibs() default {};
    }
}
