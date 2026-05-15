package com.adobexp.infralytiqs.service;

/**
 * Per-tenant Infralytiqs analytics configuration for browser SDK bootstrap.
 *
 * Each instance of this service represents one factory configuration of
 * {@link com.adobexp.infralytiqs.service.impl.TenantServiceImpl}
 * and exposes the rootPath / tenantId / siteId / dbName / analyticsServerUrl
 * tuple that the SDK bootstrap needs to initialize on a content page.
 */
public interface TenantService {

    String getRootPath();

    String getTenantId();

    String getSiteId();

    String getDbName();

    String getAnalyticsServerUrl();
}
