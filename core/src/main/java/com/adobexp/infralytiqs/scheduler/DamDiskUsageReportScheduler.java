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
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
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
 * is backed by a four-step Postman flow that creates a job
 * ({@code POST /libs/dam/gui/content/reports/generatereport.export.json}), polls
 * {@code /var/dam/reports/<jobNode>.json} for status, GETs a CSV
 * ({@code /var/dam/reports/<jobNode>/DiskSize-…csv}), then DELETEs the report node. That works
 * fine from outside AEM but is a poor fit from inside the JVM because (a) every step is an HTTP
 * loopback into the same process, (b) the polling phase is bounded by AEM's
 * {@code dam-update-asset} job queue, (c) the CSV is pre-formatted ({@code "57.6 MB"} strings —
 * not raw bytes), (d) failure of step 4 leaves orphan nodes in {@code /var/dam/reports}, and
 * (e) the CSV schema is owned by AEM and can change with platform upgrades.
 *
 * <p>This scheduler instead walks the JCR tree directly via Sling
 * {@link ResourceResolver#getResource(String) getResource} and the
 * {@link Asset} / {@link Rendition} APIs. Sizes come straight from
 * {@link Rendition#getSize()} as exact {@code long} bytes. Cluster correctness is preserved by
 * setting {@code scheduler.runOn=SINGLE} so only one author node runs the job at a time.
 *
 * <h2>Event shape — drill-down + time series in one schema</h2>
 *
 * <p>For each folder the scheduler emits exactly one event with the following dimensions /
 * metrics. The schema is designed so that <em>every</em> reporting question reduces to a single
 * {@code WHERE} clause:
 *
 * <table border="1">
 *   <caption>Per-folder event schema (dimensions and metrics)</caption>
 *   <tr><th>Field</th><th>Type</th><th>Purpose</th></tr>
 *   <tr><td>{@code folder_path}</td><td>dimension</td><td>Self path, e.g. {@code /content/dam/testdownload/subfolder1}</td></tr>
 *   <tr><td>{@code folder_parent_path}</td><td>dimension</td><td>Parent path — the drill-down pivot key</td></tr>
 *   <tr><td>{@code folder_name}</td><td>dimension</td><td>Last path segment for display</td></tr>
 *   <tr><td>{@code folder_depth}</td><td>dimension (string of int)</td><td>Distance from {@code report_root_path}</td></tr>
 *   <tr><td>{@code report_root_path}</td><td>dimension</td><td>Which configured root this folder belongs to</td></tr>
 *   <tr><td>{@code report_run_id}</td><td>dimension</td><td>UUID per scheduler run — lets the UI fetch "latest snapshot"</td></tr>
 *   <tr><td>{@code report_run_started_iso}</td><td>dimension</td><td>Wall-clock start of the run (for time series)</td></tr>
 *   <tr><td>{@code size_bytes_cumulative}</td><td>metric</td><td>Bytes including all subfolders (matches AEM CSV's SIZE column when {@link DamDiskUsageReportCfg#includeRenditions()} is true)</td></tr>
 *   <tr><td>{@code asset_count_cumulative}</td><td>metric</td><td>Asset count including all subfolders (matches AEM CSV's ASSET COUNT)</td></tr>
 *   <tr><td>{@code size_bytes_self}</td><td>metric</td><td>Bytes from this folder's direct children only — never in AEM's CSV but valuable for "what does THIS folder own?" queries</td></tr>
 *   <tr><td>{@code asset_count_self}</td><td>metric</td><td>Asset count from this folder's direct children only</td></tr>
 * </table>
 *
 * <p><b>Drill-down query pattern</b> (ClickHouse pseudo-SQL):
 * <pre>
 * -- list direct children of /content/dam/testdownload from the latest run
 * SELECT folder_path, folder_name, size_bytes_cumulative, asset_count_cumulative
 *   FROM events
 *  WHERE event_type = 'asset_disk_usage_report'
 *    AND folder_parent_path = '/content/dam/testdownload'
 *    AND report_run_id = (SELECT MAX(report_run_id)
 *                          FROM events
 *                         WHERE event_type = 'asset_disk_usage_report')
 *  ORDER BY size_bytes_cumulative DESC;
 * </pre>
 * <p>Same query shape at every drill level — only {@code folder_parent_path} changes.
 *
 * <p><b>Time series query</b> (size of a single folder over time):
 * <pre>
 * SELECT report_run_started_iso, size_bytes_cumulative
 *   FROM events
 *  WHERE event_type = 'asset_disk_usage_report'
 *    AND folder_path = '/content/dam/testdownload'
 *  ORDER BY report_run_started_iso;
 * </pre>
 *
 * <h2>Cluster + runmode placement</h2>
 *
 * <p>The component requires configuration ({@link ConfigurationPolicy#REQUIRE}) and its cfg.json
 * lives under {@code .../osgiconfig/config.author/} so it activates only on AEMaaCS author. The
 * Sling scheduler properties {@code scheduler.concurrent=false} and {@code scheduler.runOn=SINGLE}
 * are set as static OSGi properties on the component, so only one author node runs the scan and
 * never two runs overlap. The schedule itself comes from configuration via
 * {@code scheduler.period} (testing — every 60s) or {@code scheduler.expression} (production —
 * cron such as {@code "0 0 2 * * ?"} for daily at 02:00).
 *
 * <h2>Resource resolver / sub-service</h2>
 *
 * <p>Walking {@code /content/dam} requires a Sling sub-service mapping to a system user with
 * {@code jcr:read} on the root. The sub-service name is set via {@link DamDiskUsageReportCfg#subService()}
 * and defaults to {@code infralytiqs-dam-reporter}. The matching repoinit + service-user-mapper
 * configs ship alongside this component's deployed cfg.json so the operator gets a single,
 * coherent install bundle. If the resolver cannot be obtained the run aborts cleanly with an
 * ERROR log — no partial events are emitted.
 *
 * <h2>Performance bounds</h2>
 *
 * <ul>
 *   <li><b>Bounded recursion depth.</b> {@link DamDiskUsageReportCfg#maxDepth()} (default 12)
 *       caps how deep we recurse, preventing pathological deep tenants from causing stack issues
 *       or runaway runs. The DAM convention is &lt;6 levels; 12 is generous.</li>
 *   <li><b>Bounded folders per run.</b> {@link DamDiskUsageReportCfg#maxFoldersPerRun()}
 *       (default 100 000) bounds the total number of folders visited per run. A run that hits
 *       this cap emits one WARN log and stops emitting; the partial events already queued ARE
 *       shipped.</li>
 *   <li><b>Streaming, not batching.</b> Events are enqueued one per folder as we walk; we never
 *       hold the whole tree's worth of events in memory. The ingest service's queue applies its
 *       own back-pressure ({@code InfralytiqsServiceImpl#queueCapacity}).</li>
 *   <li><b>Iterative, not recursive in heap.</b> We use an explicit {@link LinkedList}
 *       work-stack so the JVM call stack stays shallow regardless of tree depth.</li>
 *   <li><b>One JCR resolver per run.</b> Acquired in {@link #run()}, closed in
 *       {@code try-with-resources}. No long-lived session.</li>
 * </ul>
 */
@Component(
        service = Runnable.class,
        immediate = false,
        configurationPid = DamDiskUsageReportScheduler.PID,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {
                Constants.SERVICE_DESCRIPTION + "=Infralytiqs | DAM Disk Usage Report Scheduler",
                // Sling scheduler hard guarantees — defined here as STATIC properties so they
                // cannot be turned off via configuration by accident. The schedule itself
                // (scheduler.expression / scheduler.period) IS configurable.
                //
                // scheduler.concurrent=false   — never start a new run while the previous one is
                //                                still walking (DAM scans can take minutes).
                // scheduler.runOn=SINGLE       — in a clustered AEMaaCS author setup, only one
                //                                node runs the scan; the others are silent.
                "scheduler.concurrent:Boolean=false",
                "scheduler.runOn=SINGLE"
        })
@Designate(ocd = DamDiskUsageReportScheduler.DamDiskUsageReportCfg.class)
public final class DamDiskUsageReportScheduler implements Runnable {

    static final String PID = "com.adobexp.infralytiqs.scheduler.DamDiskUsageReportScheduler";

    private static final Logger LOG = LoggerFactory.getLogger(DamDiskUsageReportScheduler.class);

    /** sling:Folder / sling:OrderedFolder / nt:folder — JCR types we recurse into. */
    private static final List<String> FOLDER_TYPES = Collections.unmodifiableList(Arrays.asList(
            "sling:Folder", "sling:OrderedFolder", "nt:folder"));

    @ObjectClassDefinition(
            name = "Infralytiqs DAM Disk Usage Report Scheduler",
            description = "Periodically walks one or more DAM roots and emits one Infralytiqs "
                    + "analytics event per folder, carrying both cumulative and self bytes/asset "
                    + "counts. The emitted rows directly support drill-down ("
                    + "folder_parent_path) and time-series (report_run_started_iso) queries from "
                    + "ClickHouse. Deploy the OSGi config under .../osgiconfig/config.author/ "
                    + "so this only runs on AEMaaCS author.")
    public @interface DamDiskUsageReportCfg {

        // ---- Sling scheduler keys (dots in property names ↔ underscores in Java identifiers).
        //
        // The schedule is fully driven from configuration. When scheduler.expression is set it
        // wins (cron). Otherwise scheduler.period drives a fixed-rate schedule (seconds).
        //
        // For TESTING leave scheduler.expression empty and set scheduler.period=60.
        // For PRODUCTION set scheduler.expression="0 0 2 * * ?" (every day at 02:00).
        @AttributeDefinition(
                name = "scheduler.expression",
                description = "Quartz-style cron expression. Takes precedence over scheduler.period "
                        + "when both are set. Examples: '0 0 2 * * ?' = daily 02:00; "
                        + "'0 0 2 ? * SUN' = weekly Sunday 02:00. Leave EMPTY to use scheduler.period.")
        String scheduler_expression() default "";

        @AttributeDefinition(
                name = "scheduler.period",
                description = "Fixed period in seconds. Used only when scheduler.expression is empty. "
                        + "60 is recommended for testing; switch to scheduler.expression='0 0 2 * * ?' "
                        + "for production once the implementation has been validated.")
        long scheduler_period() default 60L;

        @AttributeDefinition(
                name = "scheduler.concurrent",
                description = "Hard-coded false via component property; this attribute exists only "
                        + "to make the value visible in Felix /system/console/configMgr.")
        boolean scheduler_concurrent() default false;

        @AttributeDefinition(
                name = "scheduler.runOn",
                description = "Hard-coded SINGLE via component property; this attribute exists "
                        + "only for Felix visibility.")
        String scheduler_runOn() default "SINGLE";

        // ---- Functional configuration

        @AttributeDefinition(
                name = "Comment",
                description = "Optional textual hint for admins — unused at runtime.")
        String marker() default "";

        @AttributeDefinition(
                name = "Report root paths",
                description = "DAM roots to scan, one entry per root. Default is '/content/dam'. "
                        + "Each root is walked independently and its own report_root_path "
                        + "dimension is carried on every emitted event so the UI can scope the "
                        + "drill-down to a single tenant subtree if desired.")
        String[] reportRootPaths() default {"/content/dam"};

        @AttributeDefinition(
                name = "Include renditions in size",
                description = "When true (default), every rendition under jcr:content/renditions "
                        + "is counted (this matches the AEM Reports CSV when 'renditionsize=on' is "
                        + "set on the Postman create call). When false, only the original "
                        + "rendition is counted. Switch to false if you only care about source "
                        + "asset size on disk.")
        boolean includeRenditions() default true;

        @AttributeDefinition(
                name = "Sub-service name",
                description = "Sling sub-service mapped (via ServiceUserMapperImpl.amended-…) to a "
                        + "system user with jcr:read on the configured report root paths. The "
                        + "matching service user mapper config ships in the same package as this "
                        + "scheduler.")
        String subService() default "infralytiqs-dam-reporter";

        @AttributeDefinition(
                name = "Max recursion depth",
                description = "Hard cap on how many levels below report_root_path the scheduler "
                        + "walks. The DAM convention is fewer than 6 levels; 12 is generous "
                        + "headroom while still preventing pathological deep trees from blowing "
                        + "out the stack or making the run prohibitively long.")
        int maxDepth() default 12;

        @AttributeDefinition(
                name = "Max folders per run",
                description = "Hard cap on how many folders are visited in a single scheduler "
                        + "tick (summed across all configured roots). When reached the run logs a "
                        + "WARN and stops emitting; events already enqueued are NOT discarded. "
                        + "Default 100 000.")
        int maxFoldersPerRun() default 100_000;
    }

    @Reference
    private ResourceResolverFactory resourceResolverFactory;

    @Reference
    private InfralytiqsService ingestPipeline;

    private volatile DamDiskUsageReportCfg cfg;

    @Activate
    @Modified
    void activate(DamDiskUsageReportCfg c) {
        this.cfg = c;
        String schedule = !c.scheduler_expression().isEmpty()
                ? "cron='" + c.scheduler_expression() + "'"
                : "period=" + c.scheduler_period() + "s";
        LOG.info(
                "[{}] activated; schedule={} roots={} includeRenditions={} subService={} maxDepth={} maxFoldersPerRun={}",
                PID,
                schedule,
                Arrays.toString(c.reportRootPaths()),
                c.includeRenditions(),
                c.subService(),
                c.maxDepth(),
                c.maxFoldersPerRun());
    }

    @Override
    public void run() {
        DamDiskUsageReportCfg live = cfg;
        if (live == null) {
            LOG.warn("[{}] run skipped — no active configuration", PID);
            return;
        }

        String runId = UUID.randomUUID().toString();
        long startNanos = System.nanoTime();
        String startIso = Instant.now().toString();
        AtomicLong foldersVisited = new AtomicLong();
        AtomicLong eventsEmitted = new AtomicLong();

        LOG.info("[{}] run started — runId={} roots={} startIso={}",
                PID, runId, Arrays.toString(live.reportRootPaths()), startIso);

        Map<String, Object> authInfo = new HashMap<>();
        authInfo.put(ResourceResolverFactory.SUBSERVICE, live.subService());

        try (ResourceResolver resolver = resourceResolverFactory.getServiceResourceResolver(authInfo)) {
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
                FolderStats stats = walkRoot(root, live, runId, startIso, rootPath,
                        foldersVisited, eventsEmitted);
                LOG.info("[{}] root '{}' totals — bytes={} assets={} folders={} (runId={})",
                        PID, rootPath, stats.bytesCumulative, stats.assetsCumulative,
                        stats.foldersCumulative, runId);
            }
        } catch (LoginException ex) {
            // The most common failure on first deploy — sub-service mapping is missing. Emit a
            // descriptive ERROR with the sub-service name so the operator sees exactly which
            // ServiceUserMapperImpl.amended-… entry is required.
            LOG.error(
                    "[{}] could not obtain service resource resolver (runId={}, subService='{}'): {}. "
                            + "Verify that a 'aem-infralytiqs-integrator.core:{}' mapping exists in a "
                            + "ServiceUserMapperImpl.amended-* OSGi config and that the target system "
                            + "user has jcr:read on the configured report root paths.",
                    PID, runId, live.subService(), ex.toString(), live.subService(), ex);
            return;
        } catch (RuntimeException ex) {
            LOG.error("[{}] run failed (runId={}): {}", PID, runId, ex.toString(), ex);
            return;
        }

        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
        LOG.info("[{}] run complete — runId={} foldersVisited={} eventsEmitted={} elapsedMs={}",
                PID, runId, foldersVisited.get(), eventsEmitted.get(), elapsedMs);
    }

    /**
     * Iterative post-order walk: every folder is added to {@link FolderStats} only after its
     * children are fully measured. We use a two-pass technique on an explicit work stack:
     * the first visit pushes the folder and all its sub-folders onto the stack; the second
     * visit (when its child counters have all been merged) emits the event.
     *
     * <p>We don't recursively call {@link #walkRoot} from itself; using a heap stack keeps the
     * JVM call stack shallow regardless of tree depth, eliminating one entire class of failure.
     */
    private FolderStats walkRoot(Resource rootFolder, DamDiskUsageReportCfg c, String runId,
            String startIso, String rootPath, AtomicLong foldersVisited, AtomicLong eventsEmitted) {

        // Frame represents one folder being walked. On entry (visited=false) we discover the
        // folder's children — direct asset stats are tallied immediately, sub-folders are pushed
        // as new frames. The frame is then re-pushed with visited=true so it's processed AGAIN
        // after all sub-folder frames have been popped, by which time the child stats have been
        // merged into it via parent.merge(child).
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

                // Tally direct children: collect direct assets into frame.stats, push sub-folder
                // frames for the second pass. We iterate the resource children only once per
                // folder.
                for (Resource child : frame.folder.getChildren()) {
                    if (isFolder(child)) {
                        if (frame.depth + 1 <= c.maxDepth()) {
                            stack.push(new Frame(child, frame.depth + 1, frame.stats));
                        }
                        // else: silently truncate the subtree past maxDepth. The truncation is
                        // reflected in the parent's cumulative metrics (which won't include the
                        // skipped descendants) — operators should size maxDepth to cover the
                        // deepest reasonable DAM tenant.
                    } else if (isAsset(child)) {
                        long size = computeAssetSize(child, c.includeRenditions());
                        frame.stats.bytesSelf += size;
                        frame.stats.assetsSelf += 1L;
                    }
                    // Other node types (jcr:content, dam:AssetContent, etc.) are ignored.
                }
                // Leave frame on the stack — second pass below will pop it and emit the event.
            } else {
                // Second visit: every sub-folder frame below this one has popped and merged into
                // frame.stats already. Time to emit and merge up into our parent.
                stack.pop();

                frame.stats.foldersCumulative += 1L; // include self
                emitFolderEvent(frame, runId, startIso, rootPath);
                eventsEmitted.incrementAndGet();

                if (frame.parent != null) {
                    frame.parent.merge(frame.stats);
                } else {
                    rootStats = frame.stats; // top-of-tree result for the run summary log
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

        // size_bytes_cumulative + asset_count_cumulative are what the AEM Reports CSV would
        // call SIZE and ASSET COUNT — the row matches CSV semantics when includeRenditions=true.
        // size_bytes_self + asset_count_self are extras not in the CSV but valuable for "what
        // does THIS folder OWN (excluding subfolders)" queries.
        InfralytiqsAnalyticsPayload.Builder b =
                InfralytiqsAnalyticsPayload.builder("asset_disk_usage_report")
                        .eventSubtype("dam_disk_usage_folder_snapshot")
                        // lookupPath drives tenant routing via TenantServiceManager. Using the
                        // folder path means each folder snapshot is routed to whichever tenant
                        // configuration owns its subtree (e.g. /content/dam/testdownload may
                        // resolve to a different tenant than /content/dam/groupea).
                        .lookupPath(path)
                        .pageUrl(path)
                        .dimension("folder_path", trim(path, 2048))
                        .dimension("folder_name", trim(name, 512))
                        .dimension("folder_parent_path", trim(parent, 2048))
                        .dimension("folder_depth", Integer.toString(frame.depth))
                        .dimension("report_root_path", trim(rootPath, 2048))
                        .dimension("report_run_id", runId)
                        .dimension("report_run_started_iso", startIso)
                        .metric("size_bytes_cumulative", (double) (s.bytesSelf + s.bytesCumulative))
                        .metric("asset_count_cumulative", (double) (s.assetsSelf + s.assetsCumulative))
                        .metric("size_bytes_self", (double) s.bytesSelf)
                        .metric("asset_count_self", (double) s.assetsSelf)
                        .metric("folder_depth_metric", (double) frame.depth);

        ingestPipeline.enqueue(b.build());
    }

    /**
     * Sum of rendition sizes for a single {@code dam:Asset}. When {@code includeRenditions} is
     * false, returns only the original rendition's size (matches the AEM Reports CSV when the
     * Postman create call omits {@code renditionsize=on}).
     *
     * <p>{@link Rendition#getSize()} returns 0 for renditions that have no
     * {@code jcr:content/jcr:data} (e.g. some text-stream renditions); those simply contribute 0
     * to the sum which matches what AEM's own report does.
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
        // resourceType may carry a Sling resource type override (e.g. dam:Folder) — fall back
        // to the JCR primary type as a second check so we still recognise vanilla nt:folder.
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
     * Per-folder accumulators. {@code *Self} counts only the folder's direct asset children;
     * {@code *Cumulative} is the sum of all descendant sub-folders' (self+cumulative) values —
     * which by the post-order merge below equals the entire subtree minus the folder itself.
     * The emitted {@code size_bytes_cumulative} adds {@code bytesSelf + bytesCumulative} so it
     * matches AEM's CSV "SIZE column = full subtree size" semantics.
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
                "schedule=[expr='%s',period=%ds], roots=%s, includeRenditions=%b, subService='%s', maxDepth=%d, maxFoldersPerRun=%d",
                c.scheduler_expression(), c.scheduler_period(), Arrays.toString(c.reportRootPaths()),
                c.includeRenditions(), c.subService(), c.maxDepth(), c.maxFoldersPerRun());
    }
}
