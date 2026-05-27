package com.adobexp.infralytiqs.service.impl;

import com.adobexp.infralytiqs.service.TenantService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

@Component(service = {TenantService.class})
@Designate(ocd = TenantServiceImpl.TenantConfig.class, factory = true)
public class TenantServiceImpl implements TenantService {

    static final String PID = "com.adobexp.infralytiqs.service.impl.TenantServiceImpl";

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

    @Activate
    protected void activate(final TenantConfig tenantConfig) {
        this.tenantConfig = tenantConfig;
        this.bootstrapLibByDomain = parseBootstrapLibEntries(tenantConfig.infralytiqsClientBootstrapLibs());
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
