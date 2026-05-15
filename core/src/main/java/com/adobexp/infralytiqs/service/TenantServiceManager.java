package com.adobexp.infralytiqs.service;

/**
 * Resolves the {@link TenantService} factory configuration that owns
 * a given content path.
 *
 * Models bound to a content page (e.g. InfralytiqsBootStrap) call
 * {@link #getConfigForPath(String)} with {@code resource.getPath()} to get the
 * tenant configuration whose {@code rootPath} the page sits under.
 */
public interface TenantServiceManager {

    /**
     * Returns the matching {@link TenantService} for {@code path}, or
     * {@code null} if no factory configuration covers it.
     *
     * Match is a prefix match against {@code rootPath}; if multiple
     * configurations match, the one with the longest {@code rootPath} wins
     * so that nested tenants are resolved correctly.
     */
    TenantService getConfigForPath(String path);
}
