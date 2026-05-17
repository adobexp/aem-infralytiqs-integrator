package com.adobexp.infralytiqs.scheduler.internal;

import com.adobexp.log.Logger;
import com.adobexp.log.LoggerFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 *       {@link #parseSizeBytes(String)}.</li>
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

    /** Matches "57.6 MB" / "1.2 GB" / "512" — capture-group 1=number, 2=optional unit. */
    private static final Pattern SIZE_RE =
            Pattern.compile("^\\s*([0-9]+(?:\\.[0-9]+)?)\\s*(B|KB|MB|GB|TB|PB)?\\s*$",
                    Pattern.CASE_INSENSITIVE);

    private static final DateTimeFormatter JOB_TS_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss", Locale.ROOT);

    private final String baseUrl;
    private final String basicAuthHeader;
    private final int pollIntervalSec;
    private final int pollTimeoutSec;
    private final Duration httpRequestTimeout;
    private final ObjectMapper json = new ObjectMapper();

    /**
     * @param baseUrl loopback URL the AEM author JVM listens on, no trailing slash.
     *                {@code http://localhost:4502} is the AEMaaCS author default.
     * @param username basic-auth user (per PDF the operations team's documented
     *                 {@code report-admin}).
     * @param password basic-auth password (per PDF "delivered on request basis"). May be empty
     *                 only if the AEM instance is configured for anonymous access — which is
     *                 never the case in production.
     * @param pollIntervalSec seconds between polls of step 2. 3–10s is the sweet spot — too
     *                        short = wasted CPU, too long = report-completion-to-event latency.
     * @param pollTimeoutSec  total seconds we'll wait for {@code jobStatus=completed} before
     *                        giving up. 600 (10 min) handles tenant roots with millions of
     *                        assets.
     */
    public ReportsApiClient(String baseUrl, String username, String password,
            int pollIntervalSec, int pollTimeoutSec) {
        this.baseUrl = baseUrl == null ? "" : baseUrl.replaceAll("/+$", "");
        String credentials = (username == null ? "" : username) + ":" + (password == null ? "" : password);
        this.basicAuthHeader = "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        this.pollIntervalSec = Math.max(1, pollIntervalSec);
        this.pollTimeoutSec = Math.max(pollIntervalSec, pollTimeoutSec);
        // 60s is generous for a loopback request; report CSVs at the upper end are <10 MB.
        this.httpRequestTimeout = Duration.ofSeconds(60);
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

            // ─── STEP 2: poll until jobStatus=completed ─────────────────────────────────
            LOG.info("[ReportsApiClient] STEP 2 poll begin tenant='{}' jobNodeName='{}' pollIntervalSec={} pollTimeoutSec={} (runId={})",
                    tenantRootPath, jobNodeName, pollIntervalSec, pollTimeoutSec, runId);
            boolean ready = pollUntilCompleted(jobNodeName, runId);
            if (!ready) {
                LOG.error("[ReportsApiClient] STEP 2 poll TIMED OUT tenant='{}' jobNodeName='{}' after {}s (runId={})",
                        tenantRootPath, jobNodeName, pollTimeoutSec, runId);
                return 0;
            }
            LOG.info("[ReportsApiClient] STEP 2 poll OK tenant='{}' jobNodeName='{}' (runId={})",
                    tenantRootPath, jobNodeName, runId);

            // ─── STEP 3: download CSV ───────────────────────────────────────────────────
            LOG.info("[ReportsApiClient] STEP 3 downloadCsv tenant='{}' jobNodeName='{}' jobTitle='{}' (runId={})",
                    tenantRootPath, jobNodeName, jobTitle, runId);
            String csv = downloadCsv(jobNodeName, jobTitle);
            if (csv == null || csv.isEmpty()) {
                LOG.warn("[ReportsApiClient] STEP 3 downloadCsv returned empty body tenant='{}' (runId={})",
                        tenantRootPath, runId);
                return 0;
            }
            List<ReportsApiRow> rows = parseCsv(csv);
            LOG.info("[ReportsApiClient] STEP 3 downloadCsv OK tenant='{}' csvBytes={} parsedRows={} (runId={})",
                    tenantRootPath, csv.length(), rows.size(), runId);

            // Emit one analytics event per CSV row. We emit BEFORE STEP 4 so even if cleanup
            // fails the data still reaches ClickHouse.
            for (ReportsApiRow row : rows) {
                emitter.emit(row, tenantRootPath, jobTitle, jobNodeName, runId, startIso);
                emitted++;
            }

        } catch (RuntimeException ex) {
            LOG.error("[ReportsApiClient] flow FAILED tenant='{}' jobNodeName='{}' (runId={}): {}",
                    tenantRootPath, jobNodeName, runId, ex.toString(), ex);
        } finally {
            // ─── STEP 4: cleanup ───────────────────────────────────────────────────────
            if (jobNodeName != null) {
                try {
                    LOG.info("[ReportsApiClient] STEP 4 cleanup tenant='{}' jobNodeName='{}' (runId={})",
                            tenantRootPath, jobNodeName, runId);
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
                .timeout(httpRequestTimeout)
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
     * {@code jobStatus=completed}. Returns false on timeout. Logs one INFO line per poll so
     * Loki shows the progression.
     */
    boolean pollUntilCompleted(String jobNodeName, String runId) {
        Instant deadline = Instant.now().plusSeconds(pollTimeoutSec);
        int attempts = 0;
        while (Instant.now().isBefore(deadline)) {
            attempts++;
            HttpResponse<String> resp = exec(HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/var/dam/reports/" + jobNodeName + ".json"))
                    .timeout(httpRequestTimeout)
                    .header("Authorization", basicAuthHeader)
                    .header("Accept", "application/json")
                    .GET()
                    .build());

            if (resp.statusCode() == 200) {
                try {
                    JsonNode tree = json.readTree(resp.body());
                    JsonNode statusNode = tree.get("jobStatus");
                    String status = statusNode == null ? "<missing>" : statusNode.asText();
                    LOG.info("[ReportsApiClient] STEP 2 poll attempt={} jobStatus='{}' jobNodeName='{}' (runId={})",
                            attempts, status, jobNodeName, runId);
                    if ("completed".equalsIgnoreCase(status)) {
                        return true;
                    }
                    if ("failed".equalsIgnoreCase(status) || "error".equalsIgnoreCase(status)) {
                        LOG.error("[ReportsApiClient] STEP 2 poll jobStatus='{}' is terminal-non-success — aborting (runId={})",
                                status, runId);
                        return false;
                    }
                } catch (IOException ex) {
                    LOG.warn("[ReportsApiClient] STEP 2 poll unparseable JSON attempt={} body='{}' err={}",
                            attempts, truncate(resp.body(), 200), ex.toString());
                }
            } else {
                LOG.warn("[ReportsApiClient] STEP 2 poll HTTP {} attempt={} jobNodeName='{}' (runId={})",
                        resp.statusCode(), attempts, jobNodeName, runId);
            }

            try {
                Thread.sleep(pollIntervalSec * 1000L);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                LOG.warn("[ReportsApiClient] STEP 2 poll interrupted at attempt={} (runId={})",
                        attempts, runId);
                return false;
            }
        }
        return false;
    }

    /** STEP 3 — download the CSV body. Returns the raw response body string. */
    String downloadCsv(String jobNodeName, String jobTitle) {
        String url = baseUrl + "/var/dam/reports/" + jobNodeName + "/"
                + urlEncode(jobTitle) + ".csv";
        HttpResponse<String> resp = exec(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(httpRequestTimeout)
                .header("Authorization", basicAuthHeader)
                .header("Accept", "text/csv,*/*;q=0.5")
                .GET()
                .build());
        if (resp.statusCode() != 200) {
            LOG.error("[ReportsApiClient] STEP 3 downloadCsv HTTP {} url='{}' bodyHead='{}'",
                    resp.statusCode(), url, truncate(resp.body(), 200));
            return null;
        }
        return resp.body();
    }

    /** STEP 4 — DELETE the report node. Returns true on HTTP 2xx. */
    boolean deleteJob(String jobNodeName) {
        HttpResponse<String> resp = exec(HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/libs/dam/gui/content/reports/generatereport.export.json/" + jobNodeName))
                .timeout(httpRequestTimeout)
                .header("Authorization", basicAuthHeader)
                .DELETE()
                .build());
        return resp.statusCode() >= 200 && resp.statusCode() < 300;
    }

    /**
     * Parses the report CSV. PDF format:
     * <pre>
     * "NAME","SIZE","ASSET COUNT","PATH",
     * "images",20.1 MB,3,"/content/dam/pxp/pxp/images",
     * "pxp",20.1 MB,3,"/content/dam/pxp/pxp",
     * </pre>
     *
     * <p>The trailing comma on every line is part of the AEM CSV format. We tolerate both
     * quoted and unquoted fields and skip header / blank lines. The {@code SIZE} column is
     * parsed via {@link #parseSizeBytes(String)}.
     *
     * <p>For maximum forward-compatibility we identify the column positions by HEADER NAME
     * (case-insensitive) rather than by fixed index, in case AEM ever reorders columns.
     */
    static List<ReportsApiRow> parseCsv(String csv) {
        List<ReportsApiRow> out = new ArrayList<>();
        if (csv == null || csv.isEmpty()) {
            return out;
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
            String h = headers[i].trim().toLowerCase(Locale.ROOT);
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
            String name = cells[idxName].trim();
            String path = cells[idxPath].trim();
            long sizeBytes = parseSizeBytes(cells[idxSize]);
            int assetCount = parseInt(cells[idxAssetCount]);
            out.add(new ReportsApiRow(name, sizeBytes, assetCount, path));
        }
        return out;
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
     * Converts an AEM-Reports size string back to bytes. Examples:
     * {@code "57.6 MB" → 60397977}, {@code "1.2 GB" → 1288490188}, {@code "512" → 512},
     * {@code "20.1 MB" → 21076377}. Falls back to 0 on unparseable input.
     *
     * <p>AEM-Reports uses decimal (1000-based) units, NOT binary (1024-based). This is the
     * convention you see in the file browser column ({@code KB / MB / GB}). We follow the
     * same convention so the reported numbers match the AEM UI exactly.
     */
    static long parseSizeBytes(String raw) {
        if (raw == null) {
            return 0L;
        }
        Matcher m = SIZE_RE.matcher(raw.replace("\"", ""));
        if (!m.matches()) {
            return 0L;
        }
        double v = Double.parseDouble(m.group(1));
        String unit = m.group(2);
        if (unit == null) {
            return Math.round(v);
        }
        long mult;
        switch (unit.toUpperCase(Locale.ROOT)) {
            case "B":  mult = 1L; break;
            case "KB": mult = 1_000L; break;
            case "MB": mult = 1_000_000L; break;
            case "GB": mult = 1_000_000_000L; break;
            case "TB": mult = 1_000_000_000_000L; break;
            case "PB": mult = 1_000_000_000_000_000L; break;
            default:   mult = 1L;
        }
        return Math.round(v * mult);
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

    /** One parsed CSV row — direct mirror of an AEM-Reports CSV line. */
    public static final class ReportsApiRow {
        public final String name;
        public final long sizeBytes;
        public final int assetCount;
        public final String path;

        public ReportsApiRow(String name, long sizeBytes, int assetCount, String path) {
            this.name = name;
            this.sizeBytes = sizeBytes;
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
