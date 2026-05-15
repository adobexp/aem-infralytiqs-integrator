package com.adobexp.infralytiqs.service.impl;

import com.adobexp.infralytiqs.service.TenantService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@Component(service = {TenantService.class})
@Designate(ocd = TenantServiceImpl.TenantConfig.class, factory = true)
public class TenantServiceImpl implements TenantService {

    static final String PID = "com.adobexp.infralytiqs.service.impl.TenantServiceImpl";

    private TenantConfig tenantConfig;

    @Activate
    protected void activate(final TenantConfig tenantConfig) {
        this.tenantConfig = tenantConfig;
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
    }
}
