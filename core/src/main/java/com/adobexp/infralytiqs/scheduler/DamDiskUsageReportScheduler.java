package com.adobexp.infralytiqs.scheduler;

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
 *   <tr><td>{@code size_bytes_cumulative}</td><td>metric</td><td>Bytes incl. subfolders (matches AEM CSV)</td></tr>
 *   <tr><td>{@code asset_count_cumulative}</td><td>metric</td><td>Asset count incl. subfolders</td></tr>
 *   <tr><td>{@code size_bytes_self}</td><td>metric</td><td>Direct-child bytes only</td></tr>
 *   <tr><td>{@code asset_count_self}</td><td>metric</td><td>Direct-child asset count only</td></tr>
 * </table>
 *
 * <p><b>Drill-down query (ClickHouse):</b>
 * <pre>
 * SELECT folder_path, folder_name, size_bytes_cumulative, asset_count_cumulative
 *   FROM events
 *  WHERE event_type = 'asset_disk_usage_report'
 *    AND folder_parent_path = '/content/dam/testdownload'
 *    AND report_run_id = (SELECT MAX(report_run_id)
 *                          FROM events WHERE event_type='asset_disk_usage_report')
 *  ORDER BY size_bytes_cumulative DESC;
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
                        + "actually run the scan.")
        boolean enable_scheduler() default false;

        @AttributeDefinition(
                name = "Cron expression",
                description = "Quartz-style cron. Examples: '0 0/1 * * * ?' = every minute for "
                        + "testing; '0 0 2 * * ?' = daily 02:00 for production; "
                        + "'0 0 2 ? * SUN' = weekly Sunday 02:00. This intentionally is NOT named "
                        + "'scheduler.expression' — that name would auto-route the Runnable "
                        + "through Sling's WhiteboardHandler in parallel with our own "
                        + "programmatic scheduler.schedule() call, causing double-scheduling. We "
                        + "use 'cronExpression' so only the explicit programmatic registration "
                        + "drives the job. scheduler.period is also not supported — the "
                        + "WhiteboardHandler's expression/period fallback is unreliable on "
                        + "AEMaaCS (it silently fails when expression is empty).")
        String cronExpression() default "0 0/1 * * * ?";

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
                name = "Run on activate (one-shot)",
                description = "When true, runs the scan ONCE immediately on activate in addition "
                        + "to the cron schedule. Useful during testing so you don't have to wait "
                        + "for the next cron tick. Default false.")
        boolean runOnActivate() default false;
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
        LOG.info("[{}] activate — enable_scheduler={} cronExpression='{}' roots={} includeRenditions={} subService='{}' maxDepth={} maxFoldersPerRun={} runOnActivate={}",
                PID, c.enable_scheduler(), c.cronExpression(),
                Arrays.toString(c.reportRootPaths()), c.includeRenditions(), c.subService(),
                c.maxDepth(), c.maxFoldersPerRun(), c.runOnActivate());

        applySchedule(c);

        if (c.enable_scheduler() && c.runOnActivate()) {
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
        LOG.info("[{}] modified — re-applying configuration (enable_scheduler={} cronExpression='{}')",
                PID, c.enable_scheduler(), c.cronExpression());
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

        if (!c.enable_scheduler()) {
            LOG.warn("[{}] enable_scheduler=false — Sling Scheduler job NOT registered. Set "
                    + "enable_scheduler=true in the deployed cfg.json to activate.", PID);
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
        AtomicLong foldersVisited = new AtomicLong();
        AtomicLong eventsEmitted = new AtomicLong();

        LOG.info("[{}] run STARTED — runId={} roots={} startIso={} includeRenditions={}",
                PID, runId, Arrays.toString(live.reportRootPaths()), startIso, live.includeRenditions());

        Map<String, Object> authInfo = new HashMap<>();
        authInfo.put(ResourceResolverFactory.SUBSERVICE, live.subService());

        try (ResourceResolver resolver = resourceResolverFactory.getServiceResourceResolver(authInfo)) {
            LOG.debug("[{}] obtained service resource resolver (userID={}) for subService='{}'",
                    PID, resolver.getUserID(), live.subService());

            for (String rootPath : live.reportRootPaths()) {
                if (rootPath == null || rootPath.isEmpty() || !rootPath.startsWith("/")) {
                    LOG.warn("[{}] skipping invalid report root path '{}'", PID, rootPath);
                    continue;
                }
                Resource root = resolver.getResource(rootPath);
                if (root == null) {
                    LOG.warn("[{}] root path not present in JCR (runId={}): {}", PID, runId, rootPath);
                    continue;
                }
                LOG.info("[{}] walking root='{}' (runId={})", PID, rootPath, runId);
                FolderStats stats = walkRoot(root, live, runId, startIso, rootPath,
                        foldersVisited, eventsEmitted);
                LOG.info("[{}] root='{}' DONE — bytes={} assets={} folders={} (runId={})",
                        PID, rootPath, stats.bytesCumulative + stats.bytesSelf,
                        stats.assetsCumulative + stats.assetsSelf,
                        stats.foldersCumulative, runId);
            }
        } catch (LoginException ex) {
            LOG.error(
                    "[{}] could not obtain service resource resolver (runId={}, subService='{}'): {}. "
                            + "Verify that a 'aem-infralytiqs-integrator.core:{}=[<system-user>]' mapping exists "
                            + "in a ServiceUserMapperImpl.amended-* OSGi config and that the system user has "
                            + "jcr:read on every report root path.",
                    PID, runId, live.subService(), ex.toString(), live.subService(), ex);
            return;
        } catch (RuntimeException ex) {
            LOG.error("[{}] run FAILED (runId={}): {}", PID, runId, ex.toString(), ex);
            return;
        }

        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
        LOG.info("[{}] run COMPLETE — runId={} foldersVisited={} eventsEmitted={} elapsedMs={}",
                PID, runId, foldersVisited.get(), eventsEmitted.get(), elapsedMs);
    }

    /**
     * Iterative post-order walk: every folder is emitted only after its children are fully
     * measured. Two-pass technique on an explicit stack so the JVM call stack stays shallow
     * regardless of tree depth.
     */
    private FolderStats walkRoot(Resource rootFolder, DamDiskUsageReportCfg c, String runId,
            String startIso, String rootPath, AtomicLong foldersVisited, AtomicLong eventsEmitted) {

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
                emitFolderEvent(frame, runId, startIso, rootPath);
                eventsEmitted.incrementAndGet();
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
                        .metric("size_bytes_cumulative", (double) bytesCumul)
                        .metric("asset_count_cumulative", (double) assetsCumul)
                        .metric("size_bytes_self", (double) s.bytesSelf)
                        .metric("asset_count_self", (double) s.assetsSelf)
                        .metric("folder_depth_metric", (double) frame.depth);

        ingestPipeline.enqueue(b.build());

        LOG.info("[{}] emit folder='{}' depth={} self[bytes={},assets={}] cumul[bytes={},assets={}] runId={}",
                PID, path, frame.depth, s.bytesSelf, s.assetsSelf, bytesCumul, assetsCumul, runId);
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
     * {@code size_bytes_cumulative} = self + cumulative so it matches AEM's CSV "SIZE column =
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
                "enable_scheduler=%b, cronExpression='%s', roots=%s, includeRenditions=%b, subService='%s', maxDepth=%d, maxFoldersPerRun=%d, runOnActivate=%b",
                c.enable_scheduler(), c.cronExpression(), Arrays.toString(c.reportRootPaths()),
                c.includeRenditions(), c.subService(), c.maxDepth(), c.maxFoldersPerRun(),
                c.runOnActivate());
    }
}
