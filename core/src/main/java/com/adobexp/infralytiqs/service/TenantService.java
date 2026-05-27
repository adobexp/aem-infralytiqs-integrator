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
