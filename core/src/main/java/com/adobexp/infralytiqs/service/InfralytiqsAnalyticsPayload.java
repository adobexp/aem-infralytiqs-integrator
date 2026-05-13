package com.adobexp.infralytiqs.service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable ingest payload mirrored on the st-ck-server analytics insert contract.
 *
 * <p>The filter populates only the lightweight {@link #userIdHint()} on the request thread
 * (e.g. from {@code request.getRemoteUser()}). The Infralytiqs service later resolves the
 * hint to a fully-qualified user identity ({@link #userId()}, {@link #userEmail()},
 * {@link #displayName()}) on its own worker pool — completely off the request thread —
 * by calling {@link #withUser(String, String, String)} which returns a new payload.
 */
public final class InfralytiqsAnalyticsPayload {

    private final String eventType;
    private final String eventSubtype;
    private final String pageUrl;

    /** Cheap hint captured on the request thread; the service resolves it asynchronously. */
    private final String userIdHint;

    /** Resolved JCR user id (after async enrichment); empty until enrichment runs. */
    private final String userId;

    /** Resolved profile email (after async enrichment); empty when unknown / opted out. */
    private final String userEmail;

    /** Resolved profile display name (after async enrichment); empty when unknown. */
    private final String displayName;

    private final Map<String, String> customDimensions;
    private final Map<String, Double> customMetrics;

    private InfralytiqsAnalyticsPayload(Builder b) {
        this.eventType = Objects.requireNonNull(b.eventType, "eventType");
        this.eventSubtype = b.eventSubtype;
        this.pageUrl = b.pageUrl != null ? b.pageUrl : "";
        this.userIdHint = b.userIdHint != null ? b.userIdHint : "";
        this.userId = b.userId != null ? b.userId : "";
        this.userEmail = b.userEmail != null ? b.userEmail : "";
        this.displayName = b.displayName != null ? b.displayName : "";
        this.customDimensions =
                b.customDimensions.isEmpty()
                        ? Collections.emptyMap()
                        : Collections.unmodifiableMap(new LinkedHashMap<>(b.customDimensions));
        this.customMetrics =
                b.customMetrics.isEmpty()
                        ? Collections.emptyMap()
                        : Collections.unmodifiableMap(new LinkedHashMap<>(b.customMetrics));
    }

    public String eventType() {
        return eventType;
    }

    public String eventSubtype() {
        return eventSubtype;
    }

    public String pageUrl() {
        return pageUrl;
    }

    public String userIdHint() {
        return userIdHint;
    }

    public String userId() {
        return userId;
    }

    public String userEmail() {
        return userEmail;
    }

    public String displayName() {
        return displayName;
    }

    public Map<String, String> customDimensions() {
        return customDimensions;
    }

    public Map<String, Double> customMetrics() {
        return customMetrics;
    }

    /**
     * Returns a copy of this payload with the resolved user identity attached. Called by the
     * service's async enrichment stage; never invoked from a request thread.
     */
    public InfralytiqsAnalyticsPayload withUser(String userId, String userEmail, String displayName) {
        return withUser(userId, userEmail, displayName, null, null);
    }

    /**
     * Same as {@link #withUser(String, String, String)} but also overlays additional dimensions
     * and metrics on top of the existing ones. Used by the service to attach data computed during
     * profile enrichment (e.g. accessible DAM folders) without forcing every caller to know about
     * those keys.
     */
    public InfralytiqsAnalyticsPayload withUser(String userId, String userEmail, String displayName,
            Map<String, String> extraDimensions, Map<String, Double> extraMetrics) {
        Builder b =
                new Builder(this.eventType)
                        .eventSubtype(this.eventSubtype)
                        .pageUrl(this.pageUrl)
                        .userIdHint(this.userIdHint)
                        .userId(userId)
                        .userEmail(userEmail)
                        .displayName(displayName);
        for (Map.Entry<String, String> e : this.customDimensions.entrySet()) {
            b.dimension(e.getKey(), e.getValue());
        }
        for (Map.Entry<String, Double> e : this.customMetrics.entrySet()) {
            b.metric(e.getKey(), e.getValue());
        }
        if (extraDimensions != null) {
            for (Map.Entry<String, String> e : extraDimensions.entrySet()) {
                b.dimension(e.getKey(), e.getValue());
            }
        }
        if (extraMetrics != null) {
            for (Map.Entry<String, Double> e : extraMetrics.entrySet()) {
                b.metric(e.getKey(), e.getValue());
            }
        }
        return b.build();
    }

    public static Builder builder(String eventType) {
        return new Builder(eventType);
    }

    public static final class Builder {
        private final String eventType;
        private String eventSubtype;
        private String pageUrl = "";
        private String userIdHint = "";
        private String userId = "";
        private String userEmail = "";
        private String displayName = "";
        private final Map<String, String> customDimensions = new LinkedHashMap<>();
        private final Map<String, Double> customMetrics = new LinkedHashMap<>();

        Builder(String eventType) {
            this.eventType = eventType;
        }

        public Builder eventSubtype(String v) {
            this.eventSubtype = v;
            return this;
        }

        public Builder pageUrl(String v) {
            this.pageUrl = v;
            return this;
        }

        /** Lightweight hint captured on the request thread (e.g. {@code request.getRemoteUser()}). */
        public Builder userIdHint(String v) {
            this.userIdHint = v;
            return this;
        }

        public Builder userId(String v) {
            this.userId = v;
            return this;
        }

        public Builder userEmail(String v) {
            this.userEmail = v;
            return this;
        }

        public Builder displayName(String v) {
            this.displayName = v;
            return this;
        }

        public Builder dimension(String k, String v) {
            if (k != null && v != null) {
                customDimensions.put(k, v);
            }
            return this;
        }

        public Builder metric(String k, double v) {
            if (k != null) {
                customMetrics.put(k, v);
            }
            return this;
        }

        public InfralytiqsAnalyticsPayload build() {
            return new InfralytiqsAnalyticsPayload(this);
        }
    }
}
