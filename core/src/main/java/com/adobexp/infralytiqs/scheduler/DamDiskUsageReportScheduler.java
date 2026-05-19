package com.adobexp.infralytiqs.scheduler;

import com.adobexp.infralytiqs.scheduler.internal.AemStorageUnits;
import com.adobexp.infralytiqs.scheduler.internal.ReportsApiClient;
import com.adobexp.infralytiqs.service.InfralytiqsAnalyticsPayload;
import com.adobexp.infralytiqs.service.InfralytiqsService;
import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;
import com.day.cq.dam.api.Asset;
import com.day.cq.dam.api.Rendition;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.commons.scheduler.ScheduleOptions;
import org.apache.sling.commons.scheduler.Scheduler;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

/**
 * Scheduled DAM disk-usage scanner that streams one Infralytiqs analytics event per traversed
 * folder so the resulting ClickHouse rows directly support the product's drill-down report:
 * "click a folder, see its child folders and per-folder size; click a child, see its children".
 *
 * <h2>Why a direct JCR walk instead of AEM's 4-step Reports API</h2>
 *
 * <p>The AEMaaCS Asset Reports UI ({@code /ui#/aem/mnt/overlay/dam/gui/content/reports/reportlist.html})
 * is backed by a four-step Postman flow that creates a job, polls its status, downloads a CSV, then
 * deletes the report node. That works from outside AEM but is a poor fit from inside the JVM
 * because (a) every step is an HTTP loopback into the same process, (b) the polling phase is bound
 * to AEM's {@code dam-update-asset} job queue, (c) the CSV is pre-formatted ({@code "57.6 MB"}
 * strings — not raw bytes), (d) failure of step 4 leaves orphan nodes in {@code /var/dam/reports},
 * and (e) the CSV schema is owned by AEM and can change with platform upgrades.
 *
 * <p>This scheduler instead walks the JCR tree directly via Sling {@link ResourceResolver} and the
 * {@link Asset} / {@link Rendition} APIs. Sizes come straight from {@link Rendition#getSize()} as
 * exact {@code long} bytes. Cluster correctness is preserved by setting
 * {@code scheduler.runOn=LEADER} so only the topology leader runs the scan.
 *
 * <h2>Scheduling pattern — programmatic, not whiteboard auto-discovery</h2>
 *
 * <p>This component intentionally does <em>NOT</em> expose {@code scheduler.expression} or
 * {@code scheduler.period} as OSGi service properties on its {@link Runnable} registration.
 * Doing so triggers Sling's internal {@code WhiteboardHandler} (in
 * {@code org.apache.sling.commons.scheduler.impl}) to schedule the job automatically — but on
 * AEMaaCS the WhiteboardHandler silently fails to schedule when {@code scheduler.expression} is
 * set to an empty string (an empty cron expression makes the Quartz parser throw
 * {@code IllegalArgumentException}, which the handler logs as the unhelpful line
 * {@code ERROR Scheduling service [java.lang.Runnable] failed.} with no further context and
 * never falls back to {@code scheduler.period}).
 *
 * <p>Instead this component follows the pattern proven in production at the parent group's
 * {@code AssetNameMetadataScheduler}: inject {@link Scheduler} as an OSGi reference, build a
 * {@link ScheduleOptions} from the cron expression in {@link DamDiskUsageReportCfg}, and call
 * {@link Scheduler#schedule(Object, ScheduleOptions)} explicitly from {@code @Activate}. This
 * gives us:
 * <ul>
 *   <li>Direct, debuggable control over scheduling — every success/failure shows in the log with
 *       the actual cron expression and a clear cause if it fails.</li>
 *   <li>Clean re-scheduling on {@code @Modified} without restarting the whole component.</li>
 *   <li>Explicit cleanup on {@code @Deactivate} via {@link Scheduler#unschedule(String)} —
 *       avoiding ghost jobs after a config change.</li>
 *   <li>A boolean {@code enable_scheduler} kill switch (defaulting to {@code false}) so the
 *       cfg.json must explicitly opt in. Mirrors the reference implementation pattern.</li>
 * </ul>
 *
 * <h2>Event shape — drill-down + time series in one schema</h2>
 *
 * <p>For each folder the scheduler emits exactly one event. Every reporting question reduces to a
 * single {@code WHERE} clause:
 *
 * <table border="1">
 *   <caption>Per-folder event schema (dimensions and metrics)</caption>
 *   <tr><th>Field</th><th>Type</th><th>Purpose</th></tr>
 *   <tr><td>{@code folder_path}</td><td>dimension</td><td>Self path</td></tr>
 *   <tr><td>{@code folder_parent_path}</td><td>dimension</td><td>Parent path — drill-down pivot</td></tr>
 *   <tr><td>{@code folder_name}</td><td>dimension</td><td>Last path segment</td></tr>
 *   <tr><td>{@code folder_depth}</td><td>dimension</td><td>Distance from {@code report_root_path}</td></tr>
 *   <tr><td>{@code report_root_path}</td><td>dimension</td><td>Configured root for this row</td></tr>
 *   <tr><td>{@code report_run_id}</td><td>dimension</td><td>UUID per run — pivot for "latest snapshot"</td></tr>
 *   <tr><td>{@code report_run_started_iso}</td><td>dimension</td><td>Run wall-clock start</td></tr>
 *   <tr><td>{@code size_mb_cumulative}</td><td>metric</td><td>Decimal MB incl. subfolders ({@code 1 GB=1000 MB})</td></tr>
 *   <tr><td>{@code asset_count_cumulative}</td><td>metric</td><td>Asset count incl. subfolders</td></tr>
 *   <tr><td>{@code size_mb_self}</td><td>metric</td><td>Direct-child decimal MB only</td></tr>
 *   <tr><td>{@code asset_count_self}</td><td>metric</td><td>Direct-child asset count only</td></tr>
 * </table>
 *
 * <p><b>Drill-down query (ClickHouse):</b>
 * <pre>
 * SELECT folder_path, folder_name, size_mb_cumulative, asset_count_cumulative
 *   FROM events
 *  WHERE event_type = 'asset_disk_usage_report'
 *    AND folder_parent_path = '/content/dam/testdownload'
 *    AND report_run_id = (SELECT MAX(report_run_id)
 *                          FROM events WHERE event_type='asset_disk_usage_report')
 *  ORDER BY size_mb_cumulative DESC;
 * </pre>
 *
 * <h2>Loki observability</h2>
 *
 * <p>The deployed Loki config forwards {@code com.adobexp:DEBUG} so every log statement below
 * reaches Loki. This component emits:
 * <ul>
 *   <li>INFO on activate / re-schedule / deactivate / each run start / each run finish</li>
 *   <li>INFO on each folder event dispatched (one per folder; volume bounded by maxFoldersPerRun)</li>
 *   <li>DEBUG inside the walk for the per-folder asset/rendition tallies</li>
 *   <li>ERROR on resolver acquisition failure with the exact sub-service that needs mapping</li>
 * </ul>
 */
@Component(
        service = Runnable.class,
        immediate = true,
        configurationPid = DamDiskUsageReportScheduler.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {
                Constants.SERVICE_DESCRIPTION + "=Infralytiqs | DAM Disk Usage Report Scheduler",
                // scheduler.runOn=LEADER is the value proven in production by the parent
                // group's AssetNameMetadataScheduler. On a clustered AEMaaCS author it routes the
                // job to the topology leader; on a single-node author it always runs. Hard-coded
                // here (not exposed via OCD) so a cfg.json typo can't disable cluster correctness.
                "scheduler.runOn=LEADER"
        })
@Designate(ocd = DamDiskUsageReportScheduler.DamDiskUsageReportCfg.class)
public final class DamDiskUsageReportScheduler implements Runnable {

    static final String PID = "com.adobexp.infralytiqs.scheduler.DamDiskUsageReportScheduler";

    /**
     * Job name handed to {@link Scheduler#schedule(Object, ScheduleOptions)} via
     * {@link ScheduleOptions#name(String)}. Same string is used by
     * {@link Scheduler#unschedule(String)} on deactivate / re-schedule so we never leak a
     * previous schedule when the OSGi config is modified.
     */
    static final String SCHEDULER_JOB_NAME = PID;

    private static final Logger LOG = LoggerFactory.getLogger(DamDiskUsageReportScheduler.class);

    /** sling:Folder / sling:OrderedFolder / nt:folder — JCR types we recurse into. */
    private static final List<String> FOLDER_TYPES = Collections.unmodifiableList(Arrays.asList(
            "sling:Folder", "sling:OrderedFolder", "nt:folder"));

    @ObjectClassDefinition(
            name = "Infralytiqs DAM Disk Usage Report Scheduler",
            description = "Periodically walks one or more DAM roots and emits one Infralytiqs "
                    + "analytics event per folder. Activation requires both: (1) this OSGi config "
                    + "deployed under .../osgiconfig/config.author/ so the component activates on "
                    + "AEMaaCS author only, AND (2) enable_scheduler set to true so the cron job "
                    + "is actually registered with Sling Scheduler.")
    public @interface DamDiskUsageReportCfg {

        @AttributeDefinition(
                name = "Enable scheduler",
                description = "Master kill switch. When false (default) the component activates "
                        + "but does NOT register a Sling Scheduler job — useful to deploy the "
                        + "code without it firing. Flip to true in the deployed cfg.json to "
                        + "actually run the scan. Method name is intentionally camelCase (not "
                        + "enable_scheduler) so the OSGi property name stays 'enableScheduler' "
                        + "and matches the cfg.json key verbatim — Felix metatype's underscore "
                        + "rule would otherwise map enable_scheduler() to 'enable.scheduler' and "
                        + "silently ignore a cfg.json key written as 'enable_scheduler'.")
        boolean enableScheduler() default false;

        @AttributeDefinition(
                name = "Cron expression",
                description = "Quartz-style cron. Default '0 0 2 * * ?' = daily at 02:00 (correct "
                        + "for production: a single 23 MB AEM-Reports CSV has been observed to "
                        + "take 12 hours to generate, so anything tighter than daily would either "
                        + "skip overlapping triggers under canRunConcurrently=false or starve the "
                        + "AEM Reports job queue). Other examples: '0 0/1 * * * ?' = every "
                        + "minute (testing only — do NOT use in prod with REPORTS_API mode); "
                        + "'0 0 2 ? * SUN' = weekly Sunday 02:00. This intentionally is NOT named "
                        + "'scheduler.expression' — that name would auto-route the Runnable "
                        + "through Sling's WhiteboardHandler in parallel with our own "
                        + "programmatic scheduler.schedule() call, causing double-scheduling.")
        String cronExpression() default "0 0 2 * * ?";

        @AttributeDefinition(
                name = "Comment",
                description = "Optional textual hint for admins — unused at runtime.")
        String marker() default "";

        @AttributeDefinition(
                name = "Report root paths",
                description = "DAM roots to scan, one entry per root. Default is '/content/dam'. "
                        + "Each root is walked independently and its own report_root_path "
                        + "dimension is carried on every emitted event so the UI can scope "
                        + "drill-down to a single tenant subtree.")
        String[] reportRootPaths() default {"/content/dam"};

        @AttributeDefinition(
                name = "Include renditions in size",
                description = "When true (default), every rendition under jcr:content/renditions "
                        + "is counted (matches AEM Reports CSV with renditionsize=on). When "
                        + "false, only the original rendition is counted.")
        boolean includeRenditions() default true;

        @AttributeDefinition(
                name = "Sub-service name",
                description = "Sling sub-service mapped to a system user with jcr:read on the "
                        + "report root paths. Matching service-user-mapper + repoinit configs "
                        + "ship in the same package as this scheduler.")
        String subService() default "infralytiqs-dam-reporter";

        @AttributeDefinition(
                name = "Max recursion depth",
                description = "Hard cap on subfolder depth below report_root_path. DAM convention "
                        + "is <6; 12 is generous headroom while still preventing pathological "
                        + "deep trees from stack-blowing or running too long.")
        int maxDepth() default 12;

        @AttributeDefinition(
                name = "Max folders per run",
                description = "Hard cap on folders visited per scheduler tick (across all roots). "
                        + "On hit, the run logs a WARN and stops emitting — events already "
                        + "enqueued are NOT discarded. Default 100 000.")
        int maxFoldersPerRun() default 100_000;

        @AttributeDefinition(
                name = "Max reported folder depth (0 = unlimited)",
                description = "Drops folder rows below this depth from event emission. Depth is "
                        + "counted relative to the report root (e.g. /content/dam/foo = depth 1, "
                        + "/content/dam/foo/bar = depth 2). Value 0 disables filtering and reports "
                        + "all depths. APPLIES TO BOTH JCR_WALK AND REPORTS_API STRATEGIES.\n\n"
                        + "Why this matters at production scale: the real 23 MB sample from "
                        + "/content/dam has 141 280 folder rows across depths 0–21. Limiting to "
                        + "maxReportedFolderDepth=4 drops ~91 % of rows (12 417 kept) — a major "
                        + "performance win for ClickHouse ingestion AND query speed AND the "
                        + "in-process backlog (less pacing pressure). The discarded deep folders "
                        + "are still REFLECTED in cumulative sizes of their ancestors (which ARE "
                        + "emitted), so dashboards built on depth-limited data still show the full "
                        + "tenant's bytes — they just can't drill below the configured depth.\n\n"
                        + "JCR_WALK note: the existing 'maxDepth' attribute (default 12) controls "
                        + "RECURSION depth (we stop descending past it). This new "
                        + "'maxReportedFolderDepth' controls EMIT depth only — the walk still "
                        + "descends to maxDepth so cumulative tallies are correct, we just skip "
                        + "the per-folder event for anything below the report depth.\n\n"
                        + "Range 0–25. Default 0 (unlimited, behaviour unchanged from previous "
                        + "releases).")
        int maxReportedFolderDepth() default 0;

        @AttributeDefinition(
                name = "Run on activate (one-shot)",
                description = "When true, runs the scan ONCE immediately on activate in addition "
                        + "to the cron schedule. Useful during testing so you don't have to wait "
                        + "for the next cron tick. Default false.")
        boolean runOnActivate() default false;

        // ─── Strategy selection ───────────────────────────────────────────────────────────

        @AttributeDefinition(
                name = "Report strategy mode",
                description = "Which disk-usage strategy to run on every cron tick. "
                        + "JCR_WALK = direct in-JVM JCR traversal (default, no auth, exact bytes). "
                        + "REPORTS_API = AEM's four-step 'generatereport' API (creates job, polls, "
                        + "downloads CSV, deletes; matches the Postman flow in the PDF). "
                        + "BOTH = runs JCR_WALK then REPORTS_API in the same tick so the two "
                        + "outputs can be compared in ClickHouse via the report_strategy dimension. "
                        + "Every emitted event carries report_strategy=JCR_WALK or REPORTS_API.",
                options = {
                        @org.osgi.service.metatype.annotations.Option(label = "JCR_WALK (direct JCR traversal)", value = "JCR_WALK"),
                        @org.osgi.service.metatype.annotations.Option(label = "REPORTS_API (4-step AEM Reports API)", value = "REPORTS_API"),
                        @org.osgi.service.metatype.annotations.Option(label = "BOTH (A/B both strategies each tick)", value = "BOTH")
                })
        String mode() default "JCR_WALK";

        // ─── Reports API (PDF four-step flow) — only consulted when mode != JCR_WALK ─────

        @AttributeDefinition(
                name = "Reports API: base URL",
                description = "Loopback URL the AEM author JVM listens on, no trailing slash. "
                        + "AEMaaCS author default is http://localhost:4502. Only consulted when "
                        + "mode = REPORTS_API or BOTH.")
        String reportsApiBaseUrl() default "http://localhost:4502";

        @AttributeDefinition(
                name = "Reports API: username",
                description = "HTTP Basic auth username. Per the PDF (Section 5) the operations "
                        + "team uses 'report-admin'. Defaults to that; override if your "
                        + "environment uses a different account. Only consulted when "
                        + "mode = REPORTS_API or BOTH.")
        String reportsApiUsername() default "report-admin";

        @AttributeDefinition(
                name = "Reports API: password",
                description = "HTTP Basic auth password. Per the PDF Section 5 'will be delivered "
                        + "on request basis'. Empty by default — operator MUST supply via the "
                        + "deployed cfg.json (or via OSGi Crypto Support). Only consulted when "
                        + "mode = REPORTS_API or BOTH.",
                type = org.osgi.service.metatype.annotations.AttributeType.PASSWORD)
        String reportsApiPassword() default "";

        @AttributeDefinition(
                name = "Reports API: tenant DAM paths",
                description = "One report job is created per entry. Mirrors the PDF Section 4 "
                        + "tenant table — e.g. '/content/dam/ask-the-lion', '/content/dam/pxp', "
                        + "'/content/dam/ps', '/content/dam/visa', '/content/dam/px', "
                        + "'/content/dam/garnier', '/content/dam/dot'. Defaults to "
                        + "['/content/dam'] for a single-job all-tenant report. Only consulted "
                        + "when mode = REPORTS_API or BOTH.")
        String[] reportsApiTenantPaths() default {"/content/dam"};

        @AttributeDefinition(
                name = "Reports API: poll interval seconds (starting)",
                description = "Seconds between polls of /var/dam/reports/<jobNodeName>.json "
                        + "during STEP 2 at the start of polling. The client grows this "
                        + "geometrically (2× after 1 min, 4× after 10 min, capped at 300s) so a "
                        + "small starting value is fine even for multi-hour jobs. Default 60s.")
        int reportsApiPollIntervalSec() default 60;

        @AttributeDefinition(
                name = "Reports API: poll timeout (seconds)",
                description = "Total seconds to wait for jobStatus=completed before giving up. "
                        + "Production observation 2026-05: a 23 MB CSV on /content/dam took 12 "
                        + "hours to generate, so the default is 43200 (12 h). On timeout, the "
                        + "AEM-side job is NOT deleted (it may still be running) — operator "
                        + "must manually clean up /var/dam/reports/<jobNodeName> later.")
        int reportsApiPollTimeoutSec() default 43_200;

        @AttributeDefinition(
                name = "Reports API: download timeout (seconds)",
                description = "Per-call HTTP timeout for STEP 3 only — the GET that downloads "
                        + "the CSV body. STEPS 1/2/4 use a fixed 60 s timeout (they are tiny "
                        + "JSON requests). Default 600 (10 min) covers CSVs up to ~100 MB on a "
                        + "loopback link under load. Raise for very large CSVs.")
        int reportsApiDownloadTimeoutSec() default 600;

        @AttributeDefinition(
                name = "Reports API: emit pacing — backlog fill ratio threshold",
                description = "When the InfralytiqsService's in-memory backlog (configured via "
                        + "InfralytiqsServiceImpl.queueCapacity, default 50 000 events) crosses "
                        + "this fill ratio, the emit loop pauses until the backlog drains below "
                        + "50 % — preventing silent event drops on the non-blocking q.offer() "
                        + "inside enqueue(). At 200 000 CSV rows in production this matters: "
                        + "without pacing the queue would overflow ~4× and drop 75 % of events. "
                        + "Range 0.10 – 0.95; default 0.75 (start pacing at ~37 500 events). "
                        + "Set to 1.0 to disable pacing.")
        double reportsApiEmitPacingMaxFillRatio() default 0.75d;

        @AttributeDefinition(
                name = "Reports API: emit pacing — max wait per event (ms)",
                description = "Hard cap on how long a single emit may block waiting for the "
                        + "backlog to drain. On hit, the row is emitted anyway (and may be "
                        + "dropped by the downstream queue's q.offer() if still full) and a "
                        + "WARN is logged. Default 30000 (30s). Raise if you see frequent "
                        + "'pacing wait exceeded' warnings and the underlying ClickHouse HTTP "
                        + "pipeline is slow.")
        long reportsApiEmitPacingMaxWaitMs() default 30_000L;

        @AttributeDefinition(
                name = "Reports API: delete job after success",
                description = "STEP 4 cleanup (DELETE under /var/dam/reports). Default false keeps "
                        + "each report job node for inspection while the pipeline is being validated. "
                        + "When true, deletes only after AEM reports completed, the CSV was downloaded, "
                        + "and at least one row was emitted. Jobs that time out, fail, or emit zero rows "
                        + "are never deleted.")
        boolean reportsApiDeleteJobAfterSuccess() default false;
    }

    /** Strategy switch for {@link DamDiskUsageReportCfg#mode()}. */
    enum Mode {
        JCR_WALK, REPORTS_API, BOTH;

        static Mode parseSafe(String raw, Mode fallback) {
            if (raw == null) {
                return fallback;
            }
            try {
                return valueOf(raw.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ex) {
                return fallback;
            }
        }
    }

    @Reference
    private ResourceResolverFactory resourceResolverFactory;

    @Reference
    private InfralytiqsService ingestPipeline;

    /**
     * Sling Commons Scheduler — used PROGRAMMATICALLY (we never expose scheduler.expression /
     * scheduler.period as service properties on our own Runnable, which would route through the
     * WhiteboardHandler — that's the path that failed on AEMaaCS with the silent
     * {@code Scheduling service [java.lang.Runnable] failed.} error).
     */
    @Reference
    private Scheduler scheduler;

    private volatile DamDiskUsageReportCfg cfg;

    @Activate
    void activate(DamDiskUsageReportCfg c) {
        this.cfg = c;
        LOG.info("[{}] activate — enableScheduler={} cronExpression='{}' mode='{}' roots={} includeRenditions={} subService='{}' maxDepth={} maxFoldersPerRun={} maxReportedFolderDepth={} runOnActivate={}",
                PID, c.enableScheduler(), c.cronExpression(), c.mode(),
                Arrays.toString(c.reportRootPaths()), c.includeRenditions(), c.subService(),
                c.maxDepth(), c.maxFoldersPerRun(), c.maxReportedFolderDepth(),
                c.runOnActivate());
        // Log REPORTS_API config separately to keep the primary banner readable. Password is
        // intentionally only echoed as <set>/<unset> — never logged in clear.
        LOG.info("[{}] activate — REPORTS_API reportsApiBaseUrl='{}' reportsApiUsername='{}' reportsApiPasswordPresent={} reportsApiTenantPaths={} pollIntervalSec={} pollTimeoutSec={} downloadTimeoutSec={} emitPacingMaxFillRatio={} emitPacingMaxWaitMs={} deleteJobAfterSuccess={}",
                PID, c.reportsApiBaseUrl(), c.reportsApiUsername(),
                c.reportsApiPassword() != null && !c.reportsApiPassword().isEmpty(),
                Arrays.toString(c.reportsApiTenantPaths()),
                c.reportsApiPollIntervalSec(), c.reportsApiPollTimeoutSec(),
                c.reportsApiDownloadTimeoutSec(), c.reportsApiEmitPacingMaxFillRatio(),
                c.reportsApiEmitPacingMaxWaitMs(), c.reportsApiDeleteJobAfterSuccess());

        applySchedule(c);

        if (c.enableScheduler() && c.runOnActivate()) {
            LOG.info("[{}] runOnActivate=true — kicking off an immediate one-shot run", PID);
            // Run synchronously on the activator thread. AEMaaCS treats the OSGi activator pool
            // as short-tasks-only, so we wrap in a daemon thread to avoid blocking the bundle
            // startup if the DAM tree is large.
            Thread t = new Thread(this, "infralytiqs-dam-disk-usage-onActivate");
            t.setDaemon(true);
            t.start();
        }
    }

    @Modified
    void modified(DamDiskUsageReportCfg c) {
        LOG.info("[{}] modified — re-applying configuration (enableScheduler={} cronExpression='{}')",
                PID, c.enableScheduler(), c.cronExpression());
        this.cfg = c;
        applySchedule(c);
    }

    @Deactivate
    void deactivate() {
        LOG.info("[{}] deactivate — unscheduling job '{}'", PID, SCHEDULER_JOB_NAME);
        try {
            scheduler.unschedule(SCHEDULER_JOB_NAME);
        } catch (Exception ex) {
            // Defensive — Scheduler.unschedule normally never throws but we want a clean deactivate
            // even if the API surface evolves.
            LOG.debug("[{}] unschedule of '{}' surfaced exception (ignorable on deactivate): {}",
                    PID, SCHEDULER_JOB_NAME, ex.toString());
        }
        this.cfg = null;
    }

    /**
     * Idempotently (re-)installs the Sling Scheduler job. Always unschedules any prior job under
     * {@link #SCHEDULER_JOB_NAME} first so {@code @Modified} can change the cron expression
     * cleanly without leaking the old trigger.
     */
    private void applySchedule(DamDiskUsageReportCfg c) {
        // Always best-effort unschedule first. Sling logs DEBUG internally on no-such-name; we
        // ignore the boolean return because re-installation is desired regardless.
        try {
            boolean wasScheduled = scheduler.unschedule(SCHEDULER_JOB_NAME);
            if (wasScheduled) {
                LOG.info("[{}] previous scheduler job '{}' unscheduled (pre-modify cleanup)",
                        PID, SCHEDULER_JOB_NAME);
            }
        } catch (Exception ex) {
            LOG.debug("[{}] unschedule pre-cleanup of '{}' threw (ignored): {}",
                    PID, SCHEDULER_JOB_NAME, ex.toString());
        }

        if (!c.enableScheduler()) {
            LOG.warn("[{}] enableScheduler=false — Sling Scheduler job NOT registered. Set "
                    + "enableScheduler=true in the deployed cfg.json to activate.", PID);
            return;
        }

        String expr = c.cronExpression();
        if (expr == null || expr.trim().isEmpty()) {
            LOG.error("[{}] cronExpression is empty — refusing to schedule. Provide a "
                    + "valid Quartz cron expression (e.g. '0 0/1 * * * ?' for testing).", PID);
            return;
        }

        try {
            ScheduleOptions opts = scheduler.EXPR(expr.trim());
            opts.name(SCHEDULER_JOB_NAME);
            opts.canRunConcurrently(false);
            if (scheduler.schedule(this, opts)) {
                LOG.info("[{}] scheduled Sling Scheduler job '{}' with cron='{}' (canRunConcurrently=false)",
                        PID, SCHEDULER_JOB_NAME, expr.trim());
            } else {
                LOG.error("[{}] scheduler.schedule returned false for job '{}' cron='{}' — job NOT registered",
                        PID, SCHEDULER_JOB_NAME, expr.trim());
            }
        } catch (IllegalArgumentException ex) {
            // Quartz throws IAE on invalid cron syntax. Surface the bad expression clearly so the
            // operator can fix the cfg.json without reaching for DEBUG logs.
            LOG.error("[{}] invalid cron expression '{}' for job '{}': {}",
                    PID, expr, SCHEDULER_JOB_NAME, ex.toString(), ex);
        } catch (Exception ex) {
            LOG.error("[{}] failed to schedule job '{}' cron='{}': {}",
                    PID, SCHEDULER_JOB_NAME, expr, ex.toString(), ex);
        }
    }

    @Override
    public void run() {
        DamDiskUsageReportCfg live = cfg;
        if (live == null) {
            LOG.warn("[{}] run skipped — component is deactivating or has no active configuration", PID);
            return;
        }

        String runId = UUID.randomUUID().toString();
        long startNanos = System.nanoTime();
        String startIso = Instant.now().toString();
        Mode mode = Mode.parseSafe(live.mode(), Mode.JCR_WALK);

        LOG.info("[{}] run STARTED — runId={} mode={} startIso={}", PID, runId, mode, startIso);

        if (mode == Mode.JCR_WALK || mode == Mode.BOTH) {
            runJcrWalkStrategy(live, runId, startIso);
        }
        if (mode == Mode.REPORTS_API || mode == Mode.BOTH) {
            runReportsApiStrategy(live, runId, startIso);
        }

        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
        LOG.info("[{}] run COMPLETE — runId={} mode={} elapsedMs={}", PID, runId, mode, elapsedMs);
    }

    /**
     * Direct JCR-walk strategy. Reads every folder under every {@code reportRootPaths} entry via
     * a service-user-backed {@link ResourceResolver}, computes exact byte sizes from each
     * {@link Asset}'s {@link Rendition}s, and emits one {@code asset_disk_usage_report} row per
     * folder tagged with {@code report_strategy=JCR_WALK}.
     */
    private void runJcrWalkStrategy(DamDiskUsageReportCfg live, String runId, String startIso) {
        long stratNanos = System.nanoTime();
        AtomicLong foldersVisited = new AtomicLong();
        AtomicLong eventsEmitted = new AtomicLong();
        AtomicLong eventsSkippedByDepthFilter = new AtomicLong();
        int maxReportedDepth = Math.max(0, live.maxReportedFolderDepth());

        LOG.info("[{}] JCR_WALK strategy STARTED — runId={} roots={} includeRenditions={} subService='{}' maxReportedFolderDepth={}",
                PID, runId, Arrays.toString(live.reportRootPaths()), live.includeRenditions(),
                live.subService(), maxReportedDepth);

        Map<String, Object> authInfo = new HashMap<>();
        authInfo.put(ResourceResolverFactory.SUBSERVICE, live.subService());

        try (ResourceResolver resolver = resourceResolverFactory.getServiceResourceResolver(authInfo)) {
            LOG.debug("[{}] JCR_WALK obtained service resource resolver (userID={}) for subService='{}'",
                    PID, resolver.getUserID(), live.subService());

            for (String rootPath : live.reportRootPaths()) {
                if (rootPath == null || rootPath.isEmpty() || !rootPath.startsWith("/")) {
                    LOG.warn("[{}] JCR_WALK skipping invalid report root path '{}'", PID, rootPath);
                    continue;
                }
                Resource root = resolver.getResource(rootPath);
                if (root == null) {
                    LOG.warn("[{}] JCR_WALK root path not present in JCR (runId={}): {}",
                            PID, runId, rootPath);
                    continue;
                }
                LOG.info("[{}] JCR_WALK walking root='{}' (runId={})", PID, rootPath, runId);
                FolderStats stats = walkRoot(root, live, runId, startIso, rootPath,
                        foldersVisited, eventsEmitted, eventsSkippedByDepthFilter, maxReportedDepth);
                LOG.info("[{}] JCR_WALK root='{}' DONE — bytes={} assets={} folders={} (runId={})",
                        PID, rootPath, stats.bytesCumulative + stats.bytesSelf,
                        stats.assetsCumulative + stats.assetsSelf,
                        stats.foldersCumulative, runId);
            }
        } catch (LoginException ex) {
            LOG.error(
                    "[{}] JCR_WALK could not obtain service resource resolver (runId={}, subService='{}'): {}. "
                            + "Verify that a 'aem-infralytiqs-integrator.core:{}=[<system-user>]' mapping exists "
                            + "in a ServiceUserMapperImpl.amended-* OSGi config and that the system user has "
                            + "jcr:read on every report root path.",
                    PID, runId, live.subService(), ex.toString(), live.subService(), ex);
            return;
        } catch (RuntimeException ex) {
            LOG.error("[{}] JCR_WALK FAILED (runId={}): {}", PID, runId, ex.toString(), ex);
            return;
        }

        long elapsedMs = (System.nanoTime() - stratNanos) / 1_000_000L;
        LOG.info("[{}] JCR_WALK strategy COMPLETE — runId={} foldersVisited={} eventsEmitted={} eventsSkippedByDepthFilter={} maxReportedFolderDepth={} elapsedMs={}",
                PID, runId, foldersVisited.get(), eventsEmitted.get(),
                eventsSkippedByDepthFilter.get(), maxReportedDepth, elapsedMs);
    }

    /**
     * AEM-Reports four-step API strategy. One report job is created per
     * {@link DamDiskUsageReportCfg#reportsApiTenantPaths()} entry. Each parsed CSV row is
     * emitted as one {@code asset_disk_usage_report} event tagged with
     * {@code report_strategy=REPORTS_API}.
     *
     * <p>Note that the per-row schema differs from JCR_WALK: AEM-Reports reports flat-list
     * folders (one row per folder under the tenant root) with pre-aggregated size + asset
     * count, not the JCR-walk's separate self/cumulative tally. We map AEM's "SIZE" →
     * {@code size_mb_cumulative} and "ASSET COUNT" → {@code asset_count_cumulative} so the
     * field names line up for ClickHouse cross-strategy reporting.
     */
    private void runReportsApiStrategy(DamDiskUsageReportCfg live, String runId, String startIso) {
        long stratNanos = System.nanoTime();

        if (live.reportsApiPassword() == null || live.reportsApiPassword().isEmpty()) {
            LOG.error("[{}] REPORTS_API strategy SKIPPED — reportsApiPassword is empty. Set it "
                    + "in the deployed cfg.json (use the OSGi PASSWORD type so it's masked in "
                    + "the Felix console). runId={}", PID, runId);
            return;
        }

        String[] tenants = live.reportsApiTenantPaths();
        LOG.info("[{}] REPORTS_API strategy STARTED — runId={} baseUrl='{}' username='{}' tenants={} pollIntervalSec={} pollTimeoutSec={} deleteJobAfterSuccess={}",
                PID, runId, live.reportsApiBaseUrl(), live.reportsApiUsername(),
                Arrays.toString(tenants), live.reportsApiPollIntervalSec(),
                live.reportsApiPollTimeoutSec(), live.reportsApiDeleteJobAfterSuccess());

        ReportsApiClient client = new ReportsApiClient(
                live.reportsApiBaseUrl(),
                live.reportsApiUsername(),
                live.reportsApiPassword(),
                live.reportsApiPollIntervalSec(),
                live.reportsApiPollTimeoutSec(),
                live.reportsApiDownloadTimeoutSec(),
                live.reportsApiDeleteJobAfterSuccess());

        // Per-emit counters shared with the emit callback for periodic INFO summaries (every
        // 5 000 rows by default, to avoid 200 000 per-row INFO lines flooding Loki). The skip
        // counter tracks rows dropped by the maxReportedFolderDepth filter — useful for
        // verifying the filter is working as intended.
        final AtomicLong emitCounter = new AtomicLong();
        final AtomicLong skipCounter = new AtomicLong();
        final double pacingThreshold = clamp(live.reportsApiEmitPacingMaxFillRatio(), 0.10d, 1.0d);
        final long pacingMaxWaitMs = Math.max(0L, live.reportsApiEmitPacingMaxWaitMs());
        final int maxReportedDepth = Math.max(0, live.maxReportedFolderDepth());

        long totalEmitted = 0;
        for (String tenant : tenants) {
            try {
                int emitted = client.runForTenant(tenant,
                        (row, tenantRoot, jobTitle, jobNodeName, rId, sIso) -> {
                            // Depth-filter FIRST — before any payload construction or pacing.
                            // We compute depth from the path (very cheap: a few char scans), and
                            // when filtered we save (a) the InfralytiqsAnalyticsPayload.Builder
                            // allocation + ~10 dimension/metric writes, (b) the enqueue +
                            // queue-offer cost, (c) the pacing sleep, and (d) downstream HTTP +
                            // ClickHouse INSERT row. At 91 % drop rate (maxDepth=4 on the real
                            // production CSV) that's a ~10× speedup of the emit phase.
                            int depth = computeDepth(tenantRoot,
                                    row.path == null ? "" : row.path);
                            if (maxReportedDepth > 0 && depth > maxReportedDepth) {
                                long sk = skipCounter.incrementAndGet();
                                if (sk % EMIT_SUMMARY_EVERY == 0 && LOG.isDebugEnabled()) {
                                    LOG.debug("[{}] REPORTS_API depth-filter skipped {} rows so far (current path='{}' depth={} > maxReportedFolderDepth={}) runId={}",
                                            PID, sk, row.path, depth, maxReportedDepth, rId);
                                }
                                return;
                            }
                            paceForBacklog(pacingThreshold, pacingMaxWaitMs, rId);
                            emitReportsApiFolderEvent(row, tenantRoot, jobTitle, jobNodeName,
                                    rId, sIso, emitCounter, depth);
                        },
                        runId, startIso);
                totalEmitted += emitted;
                LOG.info("[{}] REPORTS_API tenant='{}' DONE — rowsReceived={} eventsEmitted={} eventsSkippedByDepthFilter={} maxReportedFolderDepth={} runId={}",
                        PID, tenant, emitted + skipCounter.get(), emitCounter.get(),
                        skipCounter.get(), maxReportedDepth, runId);
            } catch (RuntimeException ex) {
                LOG.error("[{}] REPORTS_API tenant='{}' FAILED runId={}: {}",
                        PID, tenant, runId, ex.toString(), ex);
            }
        }

        long elapsedMs = (System.nanoTime() - stratNanos) / 1_000_000L;
        LOG.info("[{}] REPORTS_API strategy COMPLETE — runId={} tenants={} totalEventsEmitted={} totalSkippedByDepthFilter={} maxReportedFolderDepth={} elapsedMs={}",
                PID, runId, tenants.length, totalEmitted, skipCounter.get(),
                maxReportedDepth, elapsedMs);
    }

    /**
     * Self-pacing helper: when the ingest pipeline's in-memory backlog crosses
     * {@code maxFillRatio}, sleep in 50 ms ticks until it drains below 50 % OR
     * {@code maxWaitMs} elapses. Prevents bulk emitters (this scheduler) from silently
     * overflowing the 4 096-event {@link java.util.concurrent.LinkedBlockingQueue} inside
     * {@code InfralytiqsServiceImpl.enqueue()} which drops on {@code q.offer()} failure.
     *
     * <p>Calling this once before every {@code enqueue} adds zero overhead in steady state
     * (the queue is rarely full) and a bounded {@code maxWaitMs} when it is. The HTTP
     * pipeline drains 4 096 events typically in <2 s, so the default 30 s ceiling almost
     * never fires.
     */
    private void paceForBacklog(double maxFillRatio, long maxWaitMs, String runId) {
        InfralytiqsService ingest = ingestPipeline;
        if (ingest == null) {
            return;
        }
        int size = ingest.approximateBacklogSize();
        int cap = ingest.approximateBacklogCapacity();
        if (size < 0 || cap <= 0 || cap == Integer.MAX_VALUE) {
            return; // introspection not supported / unbounded queue
        }
        if (size < cap * maxFillRatio) {
            return; // fast path — backlog is fine
        }
        long startNanos = System.nanoTime();
        long deadlineMs = maxWaitMs;
        double drainTarget = cap * 0.5d;
        while (true) {
            size = ingest.approximateBacklogSize();
            if (size < 0 || size < drainTarget) {
                return; // drained sufficiently
            }
            long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
            if (elapsedMs >= deadlineMs) {
                LOG.warn("[{}] pacing wait exceeded {}ms — backlog still at {}/{} (~{}% full); emitting anyway (runId={})",
                        PID, deadlineMs, size, cap, (size * 100) / Math.max(1, cap), runId);
                return;
            }
            try {
                Thread.sleep(50L);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static double clamp(double v, double lo, double hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    /**
     * Builds and enqueues one {@code asset_disk_usage_report} event from a parsed CSV row.
     * Mirrors {@link #emitFolderEvent(Frame, String, String, String)} field-for-field so the
     * two strategies are pivot-compatible in ClickHouse, with the {@code report_strategy}
     * dimension being the only required disambiguator.
     *
     * <p>Per-row logging is intentionally DEBUG-level only — at 200 000 rows per production
     * scan, INFO-per-row would emit ~50 MB of Loki traffic per run. The summary INFO line
     * below is emitted every {@value #EMIT_SUMMARY_EVERY} rows so an operator can verify the
     * loop is alive in real time.
     */
    private void emitReportsApiFolderEvent(ReportsApiClient.ReportsApiRow row,
            String tenantRootPath, String jobTitle, String jobNodeName, String runId,
            String startIso, AtomicLong emitCounter, int depth) {
        String path = row.path == null ? "" : row.path;
        String name = row.name == null ? nameOf(path) : row.name;
        String parent = parentOf(path);
        // 'depth' is already computed by the caller (so the same value is reused for both the
        // depth-filter check and the emit dimension — no redundant string parsing).

        InfralytiqsAnalyticsPayload.Builder b =
                InfralytiqsAnalyticsPayload.builder("asset_disk_usage_report")
                        .eventSubtype("dam_disk_usage_folder_snapshot")
                        .lookupPath(path)
                        .pageUrl(path)
                        .dimension("folder_path", trim(path, 2048))
                        .dimension("folder_name", trim(name, 512))
                        .dimension("folder_parent_path", trim(parent, 2048))
                        .dimension("folder_depth", Integer.toString(depth))
                        .dimension("report_root_path", trim(tenantRootPath, 2048))
                        .dimension("report_run_id", runId)
                        .dimension("report_run_started_iso", startIso)
                        .dimension("report_strategy", "REPORTS_API")
                        .dimension("reports_api_job_title", trim(jobTitle, 256))
                        .dimension("reports_api_job_node_name", trim(jobNodeName, 256))
                        // AEM-Reports SIZE → decimal MB (1 GB = 1000 MB) via AemStorageUnits.
                        .metric(AemStorageUnits.METRIC_MB_CUMULATIVE, row.sizeMb)
                        .metric("asset_count_cumulative", (double) row.assetCount)
                        .metric(AemStorageUnits.METRIC_MB_SELF, row.sizeMb)
                        .metric("asset_count_self", (double) row.assetCount)
                        .metric("folder_depth_metric", (double) depth);

        ingestPipeline.enqueue(b.build());

        long n = emitCounter.incrementAndGet();
        if (LOG.isDebugEnabled()) {
            LOG.debug("[{}] REPORTS_API emit folder='{}' depth={} sizeMb={} assets={} (#{} runId={})",
                    PID, path, depth, row.sizeMb, row.assetCount, n, runId);
        }
        if (n % EMIT_SUMMARY_EVERY == 0) {
            int backlogSize = ingestPipeline.approximateBacklogSize();
            int backlogCap = ingestPipeline.approximateBacklogCapacity();
            LOG.info("[{}] REPORTS_API emit progress — rowsEmitted={} backlog={}/{} runId={}",
                    PID, n, backlogSize, backlogCap, runId);
        }
    }

    /** Cadence for the INFO progress line during bulk REPORTS_API emits. */
    private static final int EMIT_SUMMARY_EVERY = 5_000;

    /**
     * Folder depth relative to {@code rootPath}. {@code /content/dam/foo} under
     * {@code /content/dam} → 1; {@code /content/dam/foo/bar} → 2. Returns 0 when {@code path}
     * equals {@code rootPath} or doesn't start with it.
     */
    static int computeDepth(String rootPath, String path) {
        if (rootPath == null || path == null) {
            return 0;
        }
        if (!path.startsWith(rootPath)) {
            return 0;
        }
        if (path.equals(rootPath)) {
            return 0;
        }
        String rest = path.substring(rootPath.length());
        if (rest.startsWith("/")) {
            rest = rest.substring(1);
        }
        if (rest.isEmpty()) {
            return 0;
        }
        int count = 1;
        for (int i = 0; i < rest.length(); i++) {
            if (rest.charAt(i) == '/') {
                count++;
            }
        }
        return count;
    }

    /**
     * Iterative post-order walk: every folder is emitted only after its children are fully
     * measured. Two-pass technique on an explicit stack so the JVM call stack stays shallow
     * regardless of tree depth.
     */
    private FolderStats walkRoot(Resource rootFolder, DamDiskUsageReportCfg c, String runId,
            String startIso, String rootPath, AtomicLong foldersVisited, AtomicLong eventsEmitted,
            AtomicLong eventsSkippedByDepthFilter, int maxReportedDepth) {

        LinkedList<Frame> stack = new LinkedList<>();
        stack.push(new Frame(rootFolder, 0, null));

        FolderStats rootStats = null;
        long maxFolders = Math.max(1, c.maxFoldersPerRun());
        boolean capWarned = false;

        while (!stack.isEmpty()) {
            Frame frame = stack.peek();

            if (foldersVisited.get() >= maxFolders) {
                if (!capWarned) {
                    LOG.warn("[{}] runId={} folders-per-run cap reached at {} — stopping further walks",
                            PID, runId, maxFolders);
                    capWarned = true;
                }
                stack.pop();
                continue;
            }

            if (!frame.visited) {
                frame.visited = true;
                foldersVisited.incrementAndGet();

                for (Resource child : frame.folder.getChildren()) {
                    if (isFolder(child)) {
                        if (frame.depth + 1 <= c.maxDepth()) {
                            stack.push(new Frame(child, frame.depth + 1, frame.stats));
                        }
                    } else if (isAsset(child)) {
                        long size = computeAssetSize(child, c.includeRenditions());
                        frame.stats.bytesSelf += size;
                        frame.stats.assetsSelf += 1L;
                    }
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("[{}] enter folder='{}' depth={} runId={}", PID,
                            frame.folder.getPath(), frame.depth, runId);
                }
            } else {
                stack.pop();
                frame.stats.foldersCumulative += 1L;
                // Always MERGE child stats into parent (preserves cumulative aggregation even
                // when deep folders are not individually emitted to ClickHouse). The emit
                // decision is independent of the merge — it's purely a filter on the
                // analytics-event stream.
                if (maxReportedDepth > 0 && frame.depth > maxReportedDepth) {
                    eventsSkippedByDepthFilter.incrementAndGet();
                } else {
                    emitFolderEvent(frame, runId, startIso, rootPath);
                    eventsEmitted.incrementAndGet();
                }
                if (frame.parent != null) {
                    frame.parent.merge(frame.stats);
                } else {
                    rootStats = frame.stats;
                }
            }
        }

        return rootStats != null ? rootStats : new FolderStats();
    }

    private void emitFolderEvent(Frame frame, String runId, String startIso, String rootPath) {
        String path = frame.folder.getPath();
        String name = nameOf(path);
        String parent = parentOf(path);
        FolderStats s = frame.stats;

        long bytesCumul = s.bytesSelf + s.bytesCumulative;
        long assetsCumul = s.assetsSelf + s.assetsCumulative;
        double mbCumul = AemStorageUnits.bytesToDecimalMegabytes(bytesCumul);
        double mbSelf = AemStorageUnits.bytesToDecimalMegabytes(s.bytesSelf);

        InfralytiqsAnalyticsPayload.Builder b =
                InfralytiqsAnalyticsPayload.builder("asset_disk_usage_report")
                        .eventSubtype("dam_disk_usage_folder_snapshot")
                        .lookupPath(path)
                        .pageUrl(path)
                        .dimension("folder_path", trim(path, 2048))
                        .dimension("folder_name", trim(name, 512))
                        .dimension("folder_parent_path", trim(parent, 2048))
                        .dimension("folder_depth", Integer.toString(frame.depth))
                        .dimension("report_root_path", trim(rootPath, 2048))
                        .dimension("report_run_id", runId)
                        .dimension("report_run_started_iso", startIso)
                        .dimension("report_strategy", "JCR_WALK")
                        .metric(AemStorageUnits.METRIC_MB_CUMULATIVE, mbCumul)
                        .metric("asset_count_cumulative", (double) assetsCumul)
                        .metric(AemStorageUnits.METRIC_MB_SELF, mbSelf)
                        .metric("asset_count_self", (double) s.assetsSelf)
                        .metric("folder_depth_metric", (double) frame.depth);

        ingestPipeline.enqueue(b.build());

        if (LOG.isDebugEnabled()) {
            LOG.debug("[{}] JCR_WALK emit folder='{}' depth={} self[bytes={},assets={}] cumul[bytes={},assets={}] runId={}",
                    PID, path, frame.depth, s.bytesSelf, s.assetsSelf, bytesCumul, assetsCumul, runId);
        }
    }

    /**
     * Sum of rendition sizes for a single {@code dam:Asset}. When {@code includeRenditions} is
     * false, returns only the original rendition's size.
     */
    static long computeAssetSize(Resource assetResource, boolean includeRenditions) {
        Asset asset = assetResource.adaptTo(Asset.class);
        if (asset == null) {
            return 0L;
        }
        if (!includeRenditions) {
            Rendition orig = asset.getOriginal();
            return orig != null ? orig.getSize() : 0L;
        }
        long total = 0L;
        for (Rendition r : asset.getRenditions()) {
            total += r.getSize();
        }
        return total;
    }

    static boolean isFolder(Resource r) {
        String type = r.getResourceType();
        if (type != null && FOLDER_TYPES.contains(type)) {
            return true;
        }
        org.apache.sling.api.resource.ValueMap vm = r.getValueMap();
        String primary = vm.get("jcr:primaryType", String.class);
        return primary != null && FOLDER_TYPES.contains(primary);
    }

    static boolean isAsset(Resource r) {
        if ("dam:Asset".equals(r.getResourceType())) {
            return true;
        }
        org.apache.sling.api.resource.ValueMap vm = r.getValueMap();
        String primary = vm.get("jcr:primaryType", String.class);
        return "dam:Asset".equals(primary);
    }

    private static String parentOf(String path) {
        int idx = path.lastIndexOf('/');
        return idx <= 0 ? "/" : path.substring(0, idx);
    }

    private static String nameOf(String path) {
        int idx = path.lastIndexOf('/');
        return idx < 0 ? path : path.substring(idx + 1);
    }

    private static String trim(String candidate, int max) {
        if (candidate == null) {
            return "";
        }
        return candidate.length() <= max ? candidate : candidate.substring(0, max);
    }

    /**
     * One node in the iterative walk. {@code visited} flips on the second pass when child
     * folders have all been merged.
     */
    private static final class Frame {
        final Resource folder;
        final int depth;
        final FolderStats parent;
        final FolderStats stats = new FolderStats();
        boolean visited;

        Frame(Resource folder, int depth, FolderStats parent) {
            this.folder = folder;
            this.depth = depth;
            this.parent = parent;
        }
    }

    /**
     * Per-folder accumulators. {@code *Self} = direct asset children only; {@code *Cumulative} =
     * sum of all descendant sub-folder (self+cumulative) values. Emitted
     * {@code size_mb_cumulative} = decimal MB converted from JCR bytes so it matches AEM's CSV
     * "SIZE column =
     * full subtree size" semantics.
     */
    static final class FolderStats {
        long bytesSelf;
        long assetsSelf;
        long bytesCumulative;
        long assetsCumulative;
        long foldersCumulative;

        void merge(FolderStats child) {
            this.bytesCumulative += child.bytesSelf + child.bytesCumulative;
            this.assetsCumulative += child.assetsSelf + child.assetsCumulative;
            this.foldersCumulative += child.foldersCumulative;
        }
    }

    /** Convenience for tests / Felix console. */
    static String describeConfig(DamDiskUsageReportCfg c) {
        return String.format(Locale.ROOT,
                "enableScheduler=%b, cronExpression='%s', roots=%s, includeRenditions=%b, subService='%s', maxDepth=%d, maxFoldersPerRun=%d, runOnActivate=%b",
                c.enableScheduler(), c.cronExpression(), Arrays.toString(c.reportRootPaths()),
                c.includeRenditions(), c.subService(), c.maxDepth(), c.maxFoldersPerRun(),
                c.runOnActivate());
    }
}
