package com.adobexp.infralytiqs.service;

/**
 * Per-tenant Infralytiqs analytics configuration for browser SDK bootstrap.
 *
 * Each instance of this service represents one factory configuration of
 * {@link com.adobexp.infralytiqs.service.impl.TenantServiceImpl}
 * and exposes the rootPath / tenantId / siteId / dbName / analyticsServerUrl
 * tuple that the SDK bootstrap needs to initialize on a content page, plus
 * the per-domain mapping that tells the SDK which client-specific bootstrap
 * JS file to download on a given request host.
 */
public interface TenantService {

    String getRootPath();

    String getTenantId();

    String getSiteId();

    String getDbName();

    String getAnalyticsServerUrl();

    /**
     * @return the Infralytiqs company id (IL-Tenants.companyId) that owns this
     *         tenant. Sent as the {@code companyId} header when exchanging the
     *         tenant credentials for a JWT at {@code POST /il/token}.
     */
    String getCompanyId();

    /**
     * @return the tenant's public client key (IL-Tenants.clientKey). Sent as
     *         the {@code clientKey} header to {@code POST /il/token}.
     */
    String getClientKey();

    /**
     * @return the tenant's client secret (IL-Tenants.clientSecret). Used both
     *         as the {@code clientSecret} header to {@code POST /il/token} and
     *         as the HMAC key to verify/decode the returned JWT.
     */
    String getClientSecret();

    /**
     * Returns a valid Infralytiqs token id for this tenant.
     * <p>
     * The implementation caches the JWT issued by {@code POST /il/token} at the
     * service-instance level and returns its {@code tokenId} claim. The cached
     * token is reused while it is still valid (per its {@code tokenExpiryTime}
     * claim); once expired (or when the cache is empty) a fresh JWT is fetched
     * from the {@code /il/token} endpoint, verified with the configured
     * {@code clientSecret}, cached, and its {@code tokenId} returned.
     *
     * @return the current {@code tokenId}, or an empty string when a token
     *         cannot be obtained (e.g. credentials not configured, or the
     *         token endpoint is unreachable).
     */
    String getToken();

    /**
     * Returns the raw, configured {@code "<host>:<path>"} entries that map
     * a request domain to the client-specific bootstrap JS file path.
     * <p>
     * Example entry:
     * {@code "psassets.publicissapient.com:/cl/publicis/ps/infralytiqs-bootstrap.min.js"}.
     * <p>
     * Returns an empty array (never {@code null}) when no entries are
     * configured.
     */
    String[] getInfralytiqsClientBootstrapLibs();

    /**
     * Resolves the configured client-bootstrap JS path for the given
     * request domain, using a case-insensitive exact match against the
     * domain prefix of each {@code "<host>:<path>"} entry in
     * {@link #getInfralytiqsClientBootstrapLibs()}.
     *
     * @param domain the {@code request.getServerName()} of the inbound
     *               request (port-less host); may be {@code null}.
     * @return the matching client-bootstrap path (e.g.
     *         {@code "/cl/publicis/ps/infralytiqs-bootstrap.min.js"}) or
     *         an empty string when no entry matches. The returned path is
     *         then surfaced as {@code window.IL_CLIENT_BOOTSTRAP_LIB} on
     *         the rendered page, where the Infralytiqs SDK resolves it
     *         against its own CDN origin and injects the bootstrap script.
     */
    String getClientBootstrapLibForDomain(String domain);
}
