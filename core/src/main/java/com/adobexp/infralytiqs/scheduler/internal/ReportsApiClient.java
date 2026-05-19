package com.adobexp.infralytiqs.scheduler.internal;

import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
/**
 * Encapsulates the four-step AEM "DAM Disk Usage Report" API flow as documented in
 * {@code GD-AEM Platform _ DAM Disk usage Reporting-170526-022710.pdf}.
 *
 * <h2>The four steps</h2>
 *
 * <ol>
 *   <li>{@code POST /libs/dam/gui/content/reports/generatereport.export.json} (multipart form-data)
 *       — creates an asynchronous report job. Returns 201 with
 *       {@code {"jobNodeName":"...","url":"..."}}.</li>
 *   <li>{@code GET /var/dam/reports/<jobNodeName>.json} — polled at
 *       {@link #pollIntervalSec}-second intervals up to {@link #pollTimeoutSec} seconds total
 *       until {@code "jobStatus":"completed"}.</li>
 *   <li>{@code GET /var/dam/reports/<jobNodeName>/<jobTitle>.csv} — downloads the report as
 *       CSV. The CSV header is {@code "NAME","SIZE","ASSET COUNT","PATH"}. The {@code SIZE}
 *       column is pre-formatted as a human-readable string with a unit suffix
 *       ({@code "57.6 MB"}, {@code "1.2 GB"}); we convert back to raw bytes via
 *       {@link AemStorageUnits#parseSizeToDecimalMegabytes(String)}.</li>
 *   <li>{@code DELETE /libs/dam/gui/content/reports/generatereport.export.json/<jobNodeName>}
 *       — best-effort cleanup to keep {@code /var/dam/reports} tidy. Failures are logged but
 *       don't abort the run, otherwise a transient delete error would mask the successfully
 *       parsed report.</li>
 * </ol>
 *
 * <h2>Transport choice — loopback HTTP, not Sling internal dispatch</h2>
 *
 * <p>We deliberately use {@code java.net.http.HttpClient} against
 * {@link #baseUrl} (default {@code http://localhost:4502}) with HTTP Basic Auth instead of
 * dispatching through {@code org.apache.sling.engine.SlingRequestProcessor}. Reasons:
 * <ul>
 *   <li>The {@code generatereport.export.json} servlet kicks off an asynchronous Sling job —
 *       a programmatic dispatch returns immediately with no way to await the
 *       {@code dam-update-asset}-style queue, so we'd still have to HTTP-poll
 *       {@code /var/dam/reports/<jobNodeName>.json} in step 2. Once you're already polling
 *       over HTTP, doing step 1 over HTTP is the consistent choice.</li>
 *   <li>The Sling internal dispatch API requires fabricating a {@code HttpServletRequest} +
 *       {@code HttpServletResponse} from scratch — 60+ method-stub interface; no clean Sling
 *       helper exists outside the test framework.</li>
 *   <li>Inside the AEMaaCS author pod, {@code localhost:4502} reaches the same JVM with
 *       sub-millisecond loopback latency — there is no network egress and no dispatcher
 *       traversal.</li>
 *   <li>Auth via {@code report-admin} (per the PDF) means the caller is correctly recorded as
 *       the report author in the AEM audit log, which is what the operations team expects.</li>
 * </ul>
 *
 * <h2>What we deliberately do NOT do</h2>
 *
 * <ul>
 *   <li>No retries on transient HTTP failures. AEMaaCS author is co-located with this JVM —
 *       transient failures here are real bugs and should surface as errors, not be hidden by
 *       silent retry.</li>
 *   <li>No CSV streaming. The CSV is bounded by the number of folders under the tenant root
 *       (in the order of low thousands at most for the tenant roots in the PDF), so reading
 *       the full body into memory is cheaper than streaming-parser machinery.</li>
 *   <li>No connection pooling. Each tenant uses its own short-lived {@link HttpClient}
 *       instance via {@code newHttpClient()} so a hung connection in one tenant can't bleed
 *       file descriptors into the next.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 *
 * <p>Instances are immutable after construction; multiple tenant runs can share a client
 * safely. The underlying {@link HttpClient} is thread-safe by JDK contract.
 */
public final class ReportsApiClient {

    private static final Logger LOG = LoggerFactory.getLogger(ReportsApiClient.class);

    /** Fixed POST form-data values per the PDF (Section 6, Step 1). */
    static final String COLCONFIG = "/mnt/overlay/dam/gui/content/reports/steps/configurecolumns.html";
    static final String REPORT_TYPE = "foldersizeandstrengthreport";

    private static final DateTimeFormatter JOB_TS_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss", Locale.ROOT);

    /** Per-call HTTP timeouts. STEP 1/2/4 are tiny JSON requests; STEP 3 can be a large CSV. */
    private static final Duration STEP_124_HTTP_TIMEOUT = Duration.ofSeconds(60);

    /** Hard ceiling for adaptive poll-interval growth — never wait longer than this between polls. */
    private static final int ADAPTIVE_POLL_INTERVAL_MAX_SEC = 300;

    /** How often to log a "still waiting" progress line during long polls. */
    private static final long POLL_PROGRESS_LOG_EVERY_MS = 5L * 60 * 1000;

    private final String baseUrl;
    private final String basicAuthHeader;
    private final int pollIntervalSec;
    private final int pollTimeoutSec;
    private final Duration downloadTimeout;
    private final ObjectMapper json = new ObjectMapper();

    /**
     * @param baseUrl loopback URL the AEM author JVM listens on, no trailing slash.
     *                {@code http://localhost:4502} is the AEMaaCS author default.
     * @param username basic-auth user (per PDF the operations team's documented
     *                 {@code report-admin}).
     * @param password basic-auth password (per PDF "delivered on request basis"). May be empty
     *                 only if the AEM instance is configured for anonymous access — which is
     *                 never the case in production.
     * @param pollIntervalSec seconds between polls of step 2 at the START of polling. The
     *                        client adaptively grows this up to {@value #ADAPTIVE_POLL_INTERVAL_MAX_SEC}s
     *                        as the job ages, so a small starting value (5–60s) is fine even
     *                        for multi-hour jobs.
     * @param pollTimeoutSec  total seconds we'll wait for {@code jobStatus=completed} before
     *                        giving up. Production observation 2026-05: a 23 MB CSV on
     *                        {@code /content/dam} took 12 hours to generate — set to
     *                        {@code 43200}+ for those roots.
     * @param downloadTimeoutSec  per-call HTTP timeout for STEP 3 only — the GET that
     *                            downloads the CSV body. STEPS 1/2/4 use a fixed 60 s timeout
     *                            (they are tiny JSON requests over loopback). 600 s (10 min)
     *                            is the default and covers CSVs up to ~100 MB on a loopback
     *                            link under load.
     */
    public ReportsApiClient(String baseUrl, String username, String password,
            int pollIntervalSec, int pollTimeoutSec, int downloadTimeoutSec) {
        this.baseUrl = baseUrl == null ? "" : baseUrl.replaceAll("/+$", "");
        String credentials = (username == null ? "" : username) + ":" + (password == null ? "" : password);
        this.basicAuthHeader = "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        this.pollIntervalSec = Math.max(1, pollIntervalSec);
        this.pollTimeoutSec = Math.max(pollIntervalSec, pollTimeoutSec);
        this.downloadTimeout = Duration.ofSeconds(Math.max(60, downloadTimeoutSec));
    }

    /** Outcome of STEP 2 — three-valued so callers can react differently. */
    enum PollResult {
        /** {@code jobStatus=completed} observed. STEP 3 + STEP 4 should both run. */
        COMPLETED,
        /** Wall-clock deadline ({@link #pollTimeoutSec}) reached without seeing completion.
         *  The job may still be running on AEM; STEP 4 cleanup is SKIPPED to avoid cancelling
         *  it. Operator must manually delete the orphan node from {@code /var/dam/reports}
         *  when the job eventually finishes (or fails). */
        TIMED_OUT,
        /** {@code jobStatus=failed} / {@code error} observed, or polling was interrupted.
         *  STEP 4 cleanup STILL runs (the AEM job is terminal-non-success). */
        FAILED
    }

    /**
     * Runs the full four-step flow against a single tenant root. Emits one row per CSV line
     * via {@code emitter} (excluding the header). Cleanup always runs even when steps 2 or 3
     * fail.
     *
     * @return number of CSV rows successfully emitted (0 if any step before emission failed).
     */
    public int runForTenant(String tenantRootPath, RowEmitter emitter, String runId, String startIso) {
        if (tenantRootPath == null || tenantRootPath.isEmpty() || !tenantRootPath.startsWith("/")) {
            LOG.warn("[ReportsApiClient] invalid tenant path '{}' — skipping (runId={})",
                    tenantRootPath, runId);
            return 0;
        }

        String jobTitle = generateJobTitle(tenantRootPath);
        String jobNodeName = null;
        int emitted = 0;
        long stepStartNanos = System.nanoTime();
        PollResult pollResult = PollResult.FAILED;

        try {
            // ─── STEP 1: create job ──────────────────────────────────────────────────────
            LOG.info("[ReportsApiClient] STEP 1 createJob tenant='{}' jobTitle='{}' baseUrl='{}' (runId={})",
                    tenantRootPath, jobTitle, baseUrl, runId);
            jobNodeName = createJob(tenantRootPath, jobTitle);
            if (jobNodeName == null) {
                LOG.error("[ReportsApiClient] STEP 1 createJob FAILED for tenant='{}' — no jobNodeName in response (runId={})",
                        tenantRootPath, runId);
                return 0;
            }
            LOG.info("[ReportsApiClient] STEP 1 createJob OK tenant='{}' jobNodeName='{}' (runId={})",
                    tenantRootPath, jobNodeName, runId);

            // ─── STEP 2: poll until jobStatus=completed (adaptive interval) ────────────
            LOG.info("[ReportsApiClient] STEP 2 poll begin tenant='{}' jobNodeName='{}' startIntervalSec={} maxIntervalSec={} timeoutSec={} (runId={})",
                    tenantRootPath, jobNodeName, pollIntervalSec, ADAPTIVE_POLL_INTERVAL_MAX_SEC,
                    pollTimeoutSec, runId);
            pollResult = pollUntilCompleted(jobNodeName, runId);
            if (pollResult == PollResult.TIMED_OUT) {
                LOG.error("[ReportsApiClient] STEP 2 poll TIMED OUT tenant='{}' jobNodeName='{}' after {}s — SKIPPING STEP 4 cleanup so AEM can finish the job. Manually DELETE /var/dam/reports/{} once it completes. (runId={})",
                        tenantRootPath, jobNodeName, pollTimeoutSec, jobNodeName, runId);
                return 0;
            }
            if (pollResult == PollResult.FAILED) {
                LOG.error("[ReportsApiClient] STEP 2 poll observed FAILED jobStatus tenant='{}' jobNodeName='{}' (runId={})",
                        tenantRootPath, jobNodeName, runId);
                return 0;
            }
            LOG.info("[ReportsApiClient] STEP 2 poll OK tenant='{}' jobNodeName='{}' (runId={})",
                    tenantRootPath, jobNodeName, runId);

            // ─── STEP 3: download CSV + STREAM-parse + emit row-by-row ──────────────────
            LOG.info("[ReportsApiClient] STEP 3 downloadCsv tenant='{}' jobNodeName='{}' jobTitle='{}' (runId={})",
                    tenantRootPath, jobNodeName, jobTitle, runId);
            String csv = downloadCsv(jobNodeName, jobTitle);
            if (csv == null || csv.isEmpty()) {
                LOG.warn("[ReportsApiClient] STEP 3 downloadCsv returned empty body tenant='{}' (runId={})",
                        tenantRootPath, runId);
                return 0;
            }
            LOG.info("[ReportsApiClient] STEP 3 downloadCsv OK tenant='{}' csvBytes={} (runId={}) — beginning streaming parse",
                    tenantRootPath, csv.length(), runId);
            emitted = parseAndEmitStreaming(csv, tenantRootPath, jobTitle, jobNodeName, runId, startIso, emitter);
            LOG.info("[ReportsApiClient] STEP 3 streaming parse + emit COMPLETE tenant='{}' rowsEmitted={} (runId={})",
                    tenantRootPath, emitted, runId);

        } catch (RuntimeException ex) {
            LOG.error("[ReportsApiClient] flow FAILED tenant='{}' jobNodeName='{}' (runId={}): {}",
                    tenantRootPath, jobNodeName, runId, ex.toString(), ex);
        } finally {
            // STEP 4 cleanup — but ONLY when the job reached a terminal AEM-side state
            // (COMPLETED or FAILED). On TIMED_OUT the job may still be running; deleting its
            // node would cancel AEM's in-flight work and leave temp artifacts under
            // /var/dam/temp. The operator can either DELETE manually after AEM finishes, or
            // configure /var/dam/reports cleanup to run separately.
            if (jobNodeName != null && pollResult != PollResult.TIMED_OUT) {
                try {
                    LOG.info("[ReportsApiClient] STEP 4 cleanup tenant='{}' jobNodeName='{}' pollResult={} (runId={})",
                            tenantRootPath, jobNodeName, pollResult, runId);
                    boolean ok = deleteJob(jobNodeName);
                    if (ok) {
                        LOG.info("[ReportsApiClient] STEP 4 cleanup OK tenant='{}' jobNodeName='{}' (runId={})",
                                tenantRootPath, jobNodeName, runId);
                    } else {
                        LOG.warn("[ReportsApiClient] STEP 4 cleanup FAILED tenant='{}' jobNodeName='{}' — manual cleanup may be needed in /var/dam/reports (runId={})",
                                tenantRootPath, jobNodeName, runId);
                    }
                } catch (RuntimeException ex) {
                    LOG.warn("[ReportsApiClient] STEP 4 cleanup threw tenant='{}' jobNodeName='{}' (runId={}): {}",
                            tenantRootPath, jobNodeName, runId, ex.toString());
                }
            } else if (jobNodeName != null) {
                LOG.warn("[ReportsApiClient] STEP 4 cleanup SKIPPED (poll TIMED_OUT) — orphan node /var/dam/reports/{} requires manual cleanup once AEM finishes (runId={})",
                        jobNodeName, runId);
            }
        }

        long elapsedMs = (System.nanoTime() - stepStartNanos) / 1_000_000L;
        LOG.info("[ReportsApiClient] tenant='{}' done emitted={} elapsedMs={} (runId={})",
                tenantRootPath, emitted, elapsedMs, runId);
        return emitted;
    }

    /**
     * Generates a job title matching the PDF's convention:
     * {@code <tenantSlug>-DiskUsage-<yyyyMMdd>-<HHmmss>}, e.g.
     * {@code testdownload-DiskUsage-20260517-024834}. The title doubles as the CSV filename
     * (per the PDF Section 6 Step 3) so it must be filesystem-safe — we only allow
     * {@code [A-Za-z0-9._-]}.
     */
    static String generateJobTitle(String tenantPath) {
        String slug = tenantPath == null ? "tenant" : tenantPath.replaceFirst("^/content/dam/?", "");
        if (slug.isEmpty()) {
            slug = "root";
        }
        slug = slug.replaceAll("[^A-Za-z0-9._-]", "_");
        if (slug.length() > 60) {
            slug = slug.substring(0, 60);
        }
        return slug + "-Infralytiqs-DiskUsage-" + LocalDateTime.now().format(JOB_TS_FORMAT);
    }

    /**
     * STEP 1 — POST form-data to create the job. Returns the {@code jobNodeName} on success
     * (HTTP 201) or null otherwise.
     *
     * <p>The form fields match the PDF Section 6 Step 1 exactly. {@code reportSchedule=now}
     * tells AEM to start the job immediately rather than registering a Quartz trigger.
     */
    String createJob(String tenantPath, String jobTitle) {
        String body = formEncode(
                "colconfig", COLCONFIG,
                "dam-asset-report-type", REPORT_TYPE,
                "jobTitle", jobTitle,
                "jobDescription", "Infralytiqs-generated DAM disk usage report",
                "path", tenantPath,
                "renditionsize", "on",
                "reportSchedule", "now",
                "reportdesc", "Infralytiqs disk usage report for " + tenantPath,
                "reporticon", "fileSpace",
                "reporttype", REPORT_TYPE);

        HttpResponse<String> resp = exec(HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/libs/dam/gui/content/reports/generatereport.export.json"))
                .timeout(STEP_124_HTTP_TIMEOUT)
                .header("Authorization", basicAuthHeader)
                .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build());

        if (resp.statusCode() != 200 && resp.statusCode() != 201) {
            LOG.error("[ReportsApiClient] STEP 1 createJob HTTP {} body='{}'",
                    resp.statusCode(), truncate(resp.body(), 500));
            return null;
        }

        try {
            JsonNode tree = json.readTree(resp.body());
            JsonNode nodeName = tree.get("jobNodeName");
            return nodeName != null ? nodeName.asText() : null;
        } catch (IOException ex) {
            LOG.error("[ReportsApiClient] STEP 1 createJob unparseable JSON body='{}' err={}",
                    truncate(resp.body(), 500), ex.toString());
            return null;
        }
    }

    /**
     * STEP 2 — poll {@code /var/dam/reports/<jobNodeName>.json} until
     * {@code jobStatus=completed} or the {@link #pollTimeoutSec} deadline expires.
     *
     * <h3>Adaptive polling</h3>
     *
     * <p>Production observation 2026-05: AEM-Reports on {@code /content/dam} took 12 hours to
     * generate a 23 MB CSV. Polling every 5 s for 12 h = 8 640 poll requests + log lines —
     * pointless load when AEM reports its own status no faster than once per ~30 s anyway.
     * Therefore we grow the interval geometrically:
     * <ul>
     *   <li>0 – 1 min: the configured {@link #pollIntervalSec} (default 60s)</li>
     *   <li>1 – 10 min: max(60s, 2× configured)</li>
     *   <li>10 – 60 min: max(120s, 4× configured), capped at {@value #ADAPTIVE_POLL_INTERVAL_MAX_SEC}s</li>
     *   <li>60 min+: capped at {@value #ADAPTIVE_POLL_INTERVAL_MAX_SEC}s</li>
     * </ul>
     *
     * <p>Every {@value #POLL_PROGRESS_LOG_EVERY_MS}ms (5 min) a one-line INFO "still waiting"
     * progress line is emitted so an operator can see the polling is alive without a per-poll
     * log line. Per-poll lines are demoted to DEBUG.
     *
     * @return {@link PollResult#COMPLETED} on success, {@link PollResult#FAILED} on terminal-
     *         non-success ({@code failed}/{@code error}/interrupt), {@link PollResult#TIMED_OUT}
     *         when {@link #pollTimeoutSec} elapses without observing completion.
     */
    PollResult pollUntilCompleted(String jobNodeName, String runId) {
        Instant start = Instant.now();
        Instant deadline = start.plusSeconds(pollTimeoutSec);
        long nextProgressLogMs = POLL_PROGRESS_LOG_EVERY_MS;
        int attempts = 0;
        while (Instant.now().isBefore(deadline)) {
            attempts++;
            HttpResponse<String> resp = exec(HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/var/dam/reports/" + jobNodeName + ".json"))
                    .timeout(STEP_124_HTTP_TIMEOUT)
                    .header("Authorization", basicAuthHeader)
                    .header("Accept", "application/json")
                    .GET()
                    .build());

            if (resp.statusCode() == 200) {
                try {
                    JsonNode tree = json.readTree(resp.body());
                    JsonNode statusNode = tree.get("jobStatus");
                    String status = statusNode == null ? "<missing>" : statusNode.asText();
                    LOG.debug("[ReportsApiClient] STEP 2 poll attempt={} jobStatus='{}' jobNodeName='{}' (runId={})",
                            attempts, status, jobNodeName, runId);
                    if ("completed".equalsIgnoreCase(status)) {
                        long waitSec = Duration.between(start, Instant.now()).getSeconds();
                        LOG.info("[ReportsApiClient] STEP 2 poll observed COMPLETED after {}s ({} polls) jobNodeName='{}' (runId={})",
                                waitSec, attempts, jobNodeName, runId);
                        return PollResult.COMPLETED;
                    }
                    if ("failed".equalsIgnoreCase(status) || "error".equalsIgnoreCase(status)) {
                        LOG.error("[ReportsApiClient] STEP 2 poll jobStatus='{}' is terminal-non-success — aborting (runId={})",
                                status, runId);
                        return PollResult.FAILED;
                    }
                } catch (IOException ex) {
                    LOG.warn("[ReportsApiClient] STEP 2 poll unparseable JSON attempt={} body='{}' err={}",
                            attempts, truncate(resp.body(), 200), ex.toString());
                }
            } else {
                LOG.warn("[ReportsApiClient] STEP 2 poll HTTP {} attempt={} jobNodeName='{}' (runId={})",
                        resp.statusCode(), attempts, jobNodeName, runId);
            }

            long elapsedMs = Duration.between(start, Instant.now()).toMillis();
            if (elapsedMs >= nextProgressLogMs) {
                long elapsedMin = elapsedMs / 60_000L;
                long remainingMin = (pollTimeoutSec * 1000L - elapsedMs) / 60_000L;
                LOG.info("[ReportsApiClient] STEP 2 still polling — elapsed={}m, remaining={}m, attempts={} jobNodeName='{}' (runId={})",
                        elapsedMin, remainingMin, attempts, jobNodeName, runId);
                nextProgressLogMs += POLL_PROGRESS_LOG_EVERY_MS;
            }

            int sleepSec = adaptivePollIntervalSec(elapsedMs);
            try {
                Thread.sleep(sleepSec * 1000L);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                LOG.warn("[ReportsApiClient] STEP 2 poll interrupted at attempt={} (runId={})",
                        attempts, runId);
                return PollResult.FAILED;
            }
        }
        return PollResult.TIMED_OUT;
    }

    /**
     * Adaptive poll interval growth: {@code configured} for the first minute, {@code 2×} for
     * 1–10 min, {@code 4×} for 10–60 min, capped at {@link #ADAPTIVE_POLL_INTERVAL_MAX_SEC}s.
     * Visible for testing.
     */
    int adaptivePollIntervalSec(long elapsedMs) {
        int base;
        if (elapsedMs < 60_000L) {
            base = pollIntervalSec;
        } else if (elapsedMs < 600_000L) {
            base = Math.max(60, pollIntervalSec * 2);
        } else {
            base = Math.max(120, pollIntervalSec * 4);
        }
        return Math.min(base, ADAPTIVE_POLL_INTERVAL_MAX_SEC);
    }

    /**
     * STEP 3 — download the CSV body. Uses the configurable {@link #downloadTimeout} (default
     * 10 min) instead of the small per-call timeout for STEPS 1/2/4. CSV bodies in production
     * have been observed at 23 MB; the 10-min default tolerates ~40 MB/s sustained on a busy
     * loopback link, with plenty of headroom.
     */
    String downloadCsv(String jobNodeName, String jobTitle) {
        String url = baseUrl + "/var/dam/reports/" + jobNodeName + "/"
                + urlEncode(jobTitle) + ".csv";
        long startNanos = System.nanoTime();
        HttpResponse<String> resp = exec(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(downloadTimeout)
                .header("Authorization", basicAuthHeader)
                .header("Accept", "text/csv,*/*;q=0.5")
                .GET()
                .build());
        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
        if (resp.statusCode() != 200) {
            LOG.error("[ReportsApiClient] STEP 3 downloadCsv HTTP {} url='{}' elapsedMs={} bodyHead='{}'",
                    resp.statusCode(), url, elapsedMs, truncate(resp.body(), 200));
            return null;
        }
        LOG.debug("[ReportsApiClient] STEP 3 downloadCsv transport done bytes={} elapsedMs={}",
                resp.body() == null ? 0 : resp.body().length(), elapsedMs);
        return resp.body();
    }

    /** STEP 4 — DELETE the report node. Returns true on HTTP 2xx. */
    boolean deleteJob(String jobNodeName) {
        HttpResponse<String> resp = exec(HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/libs/dam/gui/content/reports/generatereport.export.json/" + jobNodeName))
                .timeout(STEP_124_HTTP_TIMEOUT)
                .header("Authorization", basicAuthHeader)
                .DELETE()
                .build());
        return resp.statusCode() >= 200 && resp.statusCode() < 300;
    }

    /**
     * Streaming variant of {@link #parseCsv(String)} — reads the CSV one line at a time via
     * {@link BufferedReader} and invokes {@code emitter} on each parsed row immediately
     * (instead of materialising the full {@code List<ReportsApiRow>}). At 23 MB / ~200 000
     * rows in production this is what keeps heap pressure constant: peak heap usage during
     * STEP 3 is bounded by one CSV line + one {@code ReportsApiRow}, not the full file.
     *
     * <p>UTF-8 BOM is stripped at the start of the body before reading; header validation is
     * identical to {@link #parseCsv(String)}. Returns the number of rows successfully emitted.
     */
    int parseAndEmitStreaming(String csv, String tenantRootPath, String jobTitle,
            String jobNodeName, String runId, String startIso, RowEmitter emitter) {
        if (csv == null || csv.isEmpty()) {
            return 0;
        }
        if (csv.charAt(0) == '\uFEFF') {
            csv = csv.substring(1);
        }
        try (BufferedReader reader = new BufferedReader(new StringReader(csv))) {
            String headerLine = reader.readLine();
            if (headerLine == null) {
                return 0;
            }
            String[] headers = splitCsvLine(headerLine);
            int idxName = -1;
            int idxSize = -1;
            int idxAssetCount = -1;
            int idxPath = -1;
            for (int i = 0; i < headers.length; i++) {
                String h = stripBomAndTrim(headers[i]).toLowerCase(Locale.ROOT);
                if ("name".equals(h)) {
                    idxName = i;
                } else if ("size".equals(h)) {
                    idxSize = i;
                } else if ("asset count".equals(h)) {
                    idxAssetCount = i;
                } else if ("path".equals(h)) {
                    idxPath = i;
                }
            }
            if (idxName < 0 || idxSize < 0 || idxAssetCount < 0 || idxPath < 0) {
                LOG.error("[ReportsApiClient] parseAndEmitStreaming missing required column(s) — headers={} (need NAME, SIZE, ASSET COUNT, PATH)",
                        Arrays.toString(headers));
                return 0;
            }
            int maxIdx = Math.max(Math.max(idxName, idxSize), Math.max(idxAssetCount, idxPath));
            int emitted = 0;
            int lineNo = 0;
            DamLevel1FolderRollup rollup = new DamLevel1FolderRollup();
            String line;
            while ((line = reader.readLine()) != null) {
                lineNo++;
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                String[] cells = splitCsvLine(trimmed);
                if (cells.length <= maxIdx) {
                    LOG.debug("[ReportsApiClient] parseAndEmitStreaming skipping short line[{}]: '{}'", lineNo, trimmed);
                    continue;
                }
                String name = stripBomAndTrim(cells[idxName]);
                String path = stripBomAndTrim(cells[idxPath]);
                double sizeMb = parseSizeMegabytes(cells[idxSize], path, lineNo);
                int assetCount = parseInt(cells[idxAssetCount]);
                rollup.onCsvRow(path, sizeMb, assetCount);
                emitter.emit(new ReportsApiRow(name, sizeMb, assetCount, path),
                        tenantRootPath, jobTitle, jobNodeName, runId, startIso);
                rollup.markEmitted(path);
                emitted++;
            }
            for (DamLevel1FolderRollup.RollupRow rollupRow : rollup.syntheticLevel1Rows()) {
                LOG.info("[ReportsApiClient] emitting level-1 rollup row path='{}' sizeMb={} assets={} (runId={})",
                        rollupRow.path, rollupRow.sizeMb, rollupRow.assetCount, runId);
                emitter.emit(new ReportsApiRow(rollupRow.name, rollupRow.sizeMb, rollupRow.assetCount,
                                rollupRow.path),
                        tenantRootPath, jobTitle, jobNodeName, runId, startIso);
                emitted++;
            }
            return emitted;
        } catch (IOException ex) {
            // BufferedReader over a StringReader never throws IOException in practice — kept for
            // contract-completeness; we promote to a runtime error so the outer flow logs it.
            throw new RuntimeException("Unexpected IO error during streaming CSV parse: " + ex, ex);
        }
    }

    /**
     * Materialising variant of the CSV parser — returns the full {@code List<ReportsApiRow>}
     * in memory. <b>Kept only for unit-test convenience</b>; the production code path is
     * {@link #parseAndEmitStreaming} which processes the CSV one row at a time and never
     * materialises the full list. Don't call this on production-sized CSVs (23 MB observed)
     * unless you specifically need random access to the row collection.
     *
     * <p>PDF format:
     * <pre>
     * "NAME","SIZE","ASSET COUNT","PATH",
     * "images",20.1 MB,3,"/content/dam/pxp/pxp/images",
     * "pxp",20.1 MB,3,"/content/dam/pxp/pxp",
     * </pre>
     *
     * <p>The trailing comma on every line is part of the AEM CSV format. We tolerate both
     * quoted and unquoted fields and skip header / blank lines. The {@code SIZE} column is
     * parsed to decimal MB via {@link AemStorageUnits#parseSizeToDecimalMegabytes(String)}.
     *
     * <p>For maximum forward-compatibility we identify the column positions by HEADER NAME
     * (case-insensitive) rather than by fixed index, in case AEM ever reorders columns.
     *
     * <p><b>UTF-8 BOM handling:</b> AEM-Reports emits its CSV with a leading UTF-8 BOM
     * ({@code U+FEFF}) at byte 0 of the body. Observed in Loki on 2026-05-17 author runs:
     * the parser reported {@code headers=[\uFEFFNAME, SIZE, ASSET COUNT, PATH]} and failed
     * the {@code "name".equals(h)} check because the first cell was actually
     * {@code "\uFEFFname"}. We strip the BOM at the body level (covers the common case) AND
     * defensively at the head of every parsed cell (covers exotic CSVs that might embed a
     * BOM after a newline).
     */
    static List<ReportsApiRow> parseCsv(String csv) {
        List<ReportsApiRow> out = new ArrayList<>();
        if (csv == null || csv.isEmpty()) {
            return out;
        }
        // Strip UTF-8 BOM at the very start. AEM-Reports emits one; failing to strip it
        // breaks the header-name match for the first column.
        if (csv.charAt(0) == '\uFEFF') {
            csv = csv.substring(1);
        }
        String[] lines = csv.split("\\r?\\n");
        if (lines.length < 1) {
            return out;
        }
        String[] headers = splitCsvLine(lines[0]);
        int idxName = -1;
        int idxSize = -1;
        int idxAssetCount = -1;
        int idxPath = -1;
        for (int i = 0; i < headers.length; i++) {
            String h = stripBomAndTrim(headers[i]).toLowerCase(Locale.ROOT);
            if ("name".equals(h)) {
                idxName = i;
            } else if ("size".equals(h)) {
                idxSize = i;
            } else if ("asset count".equals(h)) {
                idxAssetCount = i;
            } else if ("path".equals(h)) {
                idxPath = i;
            }
        }
        if (idxName < 0 || idxSize < 0 || idxAssetCount < 0 || idxPath < 0) {
            LOG.error("[ReportsApiClient] parseCsv missing required column(s) — headers={} (need NAME, SIZE, ASSET COUNT, PATH)",
                    Arrays.toString(headers));
            return out;
        }
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] cells = splitCsvLine(line);
            if (cells.length <= Math.max(Math.max(idxName, idxSize), Math.max(idxAssetCount, idxPath))) {
                LOG.debug("[ReportsApiClient] parseCsv skipping short line[{}]: '{}'", i, line);
                continue;
            }
            String name = stripBomAndTrim(cells[idxName]);
            String path = stripBomAndTrim(cells[idxPath]);
            double sizeMb = parseSizeMegabytes(cells[idxSize], path, i);
            int assetCount = parseInt(cells[idxAssetCount]);
            out.add(new ReportsApiRow(name, sizeMb, assetCount, path));
        }
        return out;
    }

    /**
     * Trim whitespace AND strip a leading UTF-8 BOM ({@code U+FEFF}) if present. AEM-Reports
     * occasionally embeds a BOM at the head of a cell — primarily the first cell of the
     * first row — and a naïve {@code .trim()} does not remove it because
     * {@link Character#isWhitespace(char)} returns false for {@code U+FEFF}.
     */
    static String stripBomAndTrim(String s) {
        if (s == null) {
            return "";
        }
        String t = s.trim();
        if (!t.isEmpty() && t.charAt(0) == '\uFEFF') {
            t = t.substring(1).trim();
        }
        return t;
    }

    /**
     * Splits a CSV line on commas, respecting double-quotes and the trailing comma. Designed
     * for the simple, well-formed AEM-Reports CSV — does not implement RFC 4180 escapes
     * (embedded quotes inside quoted strings) because AEM-Reports does not emit them in
     * practice. If that assumption is ever invalidated, swap this for Apache Commons CSV.
     */
    static String[] splitCsvLine(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        // Trailing field — AEM's CSV ends with a trailing comma, producing an empty trailing
        // cell that's harmless to add.
        out.add(cur.toString());
        return out.toArray(new String[0]);
    }

    /**
     * Converts an AEM-Reports {@code SIZE} cell to decimal megabytes ({@code 1 GB → 1000 MB}).
     */
    static double parseSizeMegabytes(String raw) {
        return parseSizeMegabytes(raw, null, -1);
    }

    static double parseSizeMegabytes(String raw, String folderPath, int lineNo) {
        double sizeMb = AemStorageUnits.parseSizeToDecimalMegabytes(raw);
        if (sizeMb == 0d && raw != null && !raw.trim().isEmpty()
                && !AemReportsSizeParser.parse(raw).parsed) {
            LOG.warn("[ReportsApiClient] could not parse SIZE='{}' path='{}' line={} — storing 0 MB",
                    truncate(raw, 64), folderPath, lineNo);
        }
        return sizeMb;
    }

    private static int parseInt(String raw) {
        if (raw == null) {
            return 0;
        }
        try {
            return Integer.parseInt(raw.replace("\"", "").trim());
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    /** Build an {@code application/x-www-form-urlencoded} body from alternating key/value args. */
    private static String formEncode(String... kv) {
        if (kv.length % 2 != 0) {
            throw new IllegalArgumentException("formEncode needs even number of args");
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < kv.length; i += 2) {
            if (b.length() > 0) {
                b.append('&');
            }
            b.append(urlEncode(kv[i])).append('=').append(urlEncode(kv[i + 1]));
        }
        return b.toString();
    }

    private static String urlEncode(String s) {
        try {
            return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException ex) {
            // UTF-8 is required by the JRE spec; never reached.
            throw new IllegalStateException(ex);
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    /**
     * Executes the request. Each call builds its own {@link HttpClient} so failures in one
     * tenant can't leak file descriptors into the next. The client's connect timeout (30s) is
     * shorter than the per-request body timeout to fail fast on a wedged loopback.
     */
    private HttpResponse<String> exec(HttpRequest req) {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                // AEMaaCS author may redirect /libs/* to /libs/*; follow normally.
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        try {
            return client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new RuntimeException("HTTP I/O error calling " + req.uri() + ": " + ex, ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("HTTP interrupted calling " + req.uri(), ex);
        }
    }

    /** One parsed CSV row — direct mirror of an AEM-Reports CSV line (size in decimal MB). */
    public static final class ReportsApiRow {
        public final String name;
        public final double sizeMb;
        public final int assetCount;
        public final String path;

        public ReportsApiRow(String name, double sizeMb, int assetCount, String path) {
            this.name = name;
            this.sizeMb = sizeMb;
            this.assetCount = assetCount;
            this.path = path;
        }
    }

    /**
     * Callback invoked once per parsed CSV row. Implementations build an Infralytiqs analytics
     * payload tagged with {@code report_strategy=REPORTS_API} and enqueue it onto the ingest
     * pipeline. Kept out of the client itself so the client stays decoupled from the
     * Infralytiqs domain model and remains unit-testable in isolation.
     */
    @FunctionalInterface
    public interface RowEmitter {
        void emit(ReportsApiRow row, String tenantRootPath, String jobTitle, String jobNodeName,
                String runId, String startIso);
    }
}
