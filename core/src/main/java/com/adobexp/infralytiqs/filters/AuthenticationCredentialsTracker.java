package com.adobexp.infralytiqs.filters;

import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.AuthenticationInfoPostProcessor;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

/**
 * Captures authentication events that the {@link AuthenticationTrackingFilter} can never see.
 *
 * <p>Sling's {@code FormAuthenticationHandler} consumes {@code /j_security_check} requests inside
 * {@code SlingAuthenticator.handleSecurity()} — it writes the {@code login-token} cookie + 200/302
 * response itself and short-circuits the request before any Servlet Filter (Sling- or HTTP
 * Whiteboard-scoped) can wrap the response. As a result, patterns whose URL suffix is
 * {@code /j_security_check} (Pattern 2 OIDC fragment, Pattern 3 basic form) would never fire from
 * a filter, no matter how it is registered.
 *
 * <p>The Sling SPI {@link AuthenticationInfoPostProcessor#postProcess} is invoked from inside
 * {@code handleSecurity()} after an {@code AuthenticationHandler} successfully extracted
 * credentials and BEFORE the JCR login attempt. By matching the configured pattern set against
 * the request seen at this stage, we capture {@code /j_security_check} authentications with the
 * authenticated username (from {@link AuthenticationInfo#getUser()}) without any further wrapping.
 *
 * <p>The component shares the same configuration PID as
 * {@link AuthenticationTrackingFilter} so adding/removing patterns updates both entry points
 * atomically. Both honour {@link ConfigurationPolicy#REQUIRE} so neither activates without an
 * OSGi configuration. Per the user's design, patterns whose suffix is NOT {@code /j_security_check}
 * are intentionally ignored here — they belong to the filter's domain (SAML POST, etc.).
 */
@Component(
        service = AuthenticationInfoPostProcessor.class,
        immediate = false,
        configurationPid = AuthenticationTrackingFilter.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE)
public final class AuthenticationCredentialsTracker implements AuthenticationInfoPostProcessor {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationCredentialsTracker.class);

    /**
     * URL suffixes that Sling's authenticator always handles inside {@code handleSecurity()},
     * short-circuiting the request before any Servlet Filter (Sling- or whiteboard-scoped) can
     * see the response. Patterns whose suffix is in this set are routed to this post-processor;
     * everything else stays with {@link AuthenticationTrackingFilter} so we never double-count.
     */
    private static final java.util.Set<String> AUTH_SHORT_CIRCUIT_SUFFIXES =
            java.util.Collections.unmodifiableSet(new java.util.LinkedHashSet<>(java.util.Arrays.asList(
                    "/j_security_check",
                    "/saml_login")));

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile InfralytiqsService ingestPipeline;

    /**
     * Subset of patterns this component is concerned with — only those whose URL suffix is
     * {@value #SECURITY_CHECK_SUFFIX}. Volatile so {@link #postProcess} sees a coherent snapshot.
     */
    private volatile List<AuthenticationTrackingFilter.MatchRule> rules = Collections.emptyList();

    @Activate
    @Modified
    protected void activate(AuthenticationTrackingFilter.AuthFilterCfg cfg) {
        applyConfig(cfg);
    }

    private void applyConfig(AuthenticationTrackingFilter.AuthFilterCfg cfg) {
        String[] entries = cfg == null ? null : cfg.patterns();
        if (entries == null || entries.length == 0) {
            this.rules = Collections.emptyList();
            return;
        }
        List<AuthenticationTrackingFilter.MatchRule> compiled = new ArrayList<>(entries.length);
        for (int i = 0; i < entries.length; i++) {
            String raw = entries[i];
            if (raw == null || raw.trim().isEmpty()) {
                continue;
            }
            try {
                AuthenticationTrackingFilter.MatchRule rule = AuthenticationTrackingFilter.parseRule(raw);
                rule.declarationOrder = i;
                if (isAuthShortCircuitSuffix(rule.urlSuffix)) {
                    compiled.add(rule);
                }
            } catch (IllegalArgumentException ex) {
                // The filter component already logs the same parse failure with the same level —
                // we stay silent to avoid duplicate noise.
            }
        }
        compiled.sort((a, b) -> {
            int byPrio = Integer.compare(a.priority, b.priority);
            return byPrio != 0 ? byPrio : Integer.compare(a.declarationOrder, b.declarationOrder);
        });
        this.rules = Collections.unmodifiableList(compiled);
        LOG.info("[{}] authentication post-processor active with {} short-circuited auth rule(s) {}",
                AuthenticationTrackingFilter.PID, compiled.size(), AUTH_SHORT_CIRCUIT_SUFFIXES);
    }

    private static boolean isAuthShortCircuitSuffix(String urlSuffix) {
        if (urlSuffix == null) {
            return false;
        }
        for (String s : AUTH_SHORT_CIRCUIT_SUFFIXES) {
            if (s.equalsIgnoreCase(urlSuffix)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void postProcess(AuthenticationInfo info, HttpServletRequest request, HttpServletResponse response) {
        if (info == null || request == null) {
            return;
        }
        List<AuthenticationTrackingFilter.MatchRule> snapshot = rules;
        if (snapshot.isEmpty()) {
            return;
        }
        String uri = Objects.toString(request.getRequestURI(), "");
        boolean uriShortCircuited = false;
        for (String s : AUTH_SHORT_CIRCUIT_SUFFIXES) {
            if (AuthenticationTrackingFilter.endsWithInsensitive(uri, s)) {
                uriShortCircuited = true;
                break;
            }
        }
        if (!uriShortCircuited) {
            return;
        }
        String method = Objects.toString(request.getMethod(), "GET");

        // Match against the configured /j_security_check rules. Status/cookie checks from the
        // filter DSL are intentionally NOT applied here — at post-process time the response has
        // not been written yet. By contract, postProcess is invoked only when an
        // AuthenticationHandler accepted the credentials, so reaching this code path is a
        // sufficient (if slightly optimistic) success signal for /j_security_check, where the
        // subsequent JCR login virtually never fails for already-extracted form credentials.
        for (AuthenticationTrackingFilter.MatchRule rule : snapshot) {
            if (!rule.method.equalsIgnoreCase(method)) {
                continue;
            }
            if (!AuthenticationTrackingFilter.endsWithInsensitive(uri, rule.urlSuffix)) {
                continue;
            }
            if (!rule.queryParams.isEmpty()
                    && !AuthenticationTrackingFilter.allParamsHaveValue(request, rule.queryParams)) {
                continue;
            }
            if (!rule.formParams.isEmpty()
                    && !AuthenticationTrackingFilter.allParamsHaveValue(request, rule.formParams)) {
                continue;
            }

            InfralytiqsService ingest = ingestPipeline;
            if (ingest == null) {
                LOG.warn("[{}] post-process matched {} but ingestion service inactive",
                        AuthenticationTrackingFilter.PID, rule.name);
                return;
            }

            String userIdHint = info.getUser();
            if (userIdHint == null || userIdHint.isEmpty()) {
                userIdHint = request.getRemoteUser();
            }

            // For status we report the rule's primary expected code; the actual response status
            // (which we cannot observe here) is virtually always identical to it because the
            // FormAuthenticationHandler writes the standard success response on accepted credentials.
            int reportedStatus = rule.exactStatuses.isEmpty()
                    ? HttpServletResponse.SC_OK
                    : rule.exactStatuses.get(0);

            InfralytiqsAnalyticsPayload payload = AuthenticationTrackingFilter.buildPayload(
                    request, rule.name, rule.subtype, rule.eventType, reportedStatus, userIdHint);

            ingest.enqueue(payload);
            LOG.debug("[{}] post-process dispatched {} analytics ({}) for {}",
                    AuthenticationTrackingFilter.PID, rule.eventType, rule.name,
                    safeUserDisplay(userIdHint));
            return;
        }
    }

    private static String safeUserDisplay(String userId) {
        if (userId == null || userId.isEmpty()) {
            return "<anonymous>";
        }
        return userId.length() > 64 ? userId.substring(0, 64).toLowerCase(Locale.ROOT) : userId;
    }
}
