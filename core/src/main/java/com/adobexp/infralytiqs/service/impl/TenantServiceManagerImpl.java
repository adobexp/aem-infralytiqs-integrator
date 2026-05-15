package com.adobexp.infralytiqs.service.impl;

import com.adobexp.infralytiqs.service.TenantService;
import com.adobexp.infralytiqs.service.TenantServiceManager;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

@Component(
        name = "Infralytiqs — TenantServiceManager",
        immediate = true,
        service = TenantServiceManager.class)
public class TenantServiceManagerImpl implements TenantServiceManager {

    @Reference(
            cardinality = ReferenceCardinality.MULTIPLE,
            bind = "bindConfig",
            unbind = "unbindConfig",
            policy = ReferencePolicy.DYNAMIC,
            service = TenantService.class)
    private volatile List<TenantService> configList;

    public void bindConfig(final TenantService config) {
        if (configList == null) {
            configList = new ArrayList<>();
        }
        configList.add(config);
    }

    public void unbindConfig(final TenantService config) {
        if (configList != null) {
            configList.remove(config);
        }
    }

    @Override
    public TenantService getConfigForPath(String path) {
        if (this.configList == null || path == null) {
            return null;
        }
        return configList.stream()
                .filter(config -> config.getRootPath() != null
                        && !config.getRootPath().isEmpty()
                        && path.startsWith(config.getRootPath()))
                .max(Comparator.comparingInt(c -> c.getRootPath().length()))
                .orElse(null);
    }
}
