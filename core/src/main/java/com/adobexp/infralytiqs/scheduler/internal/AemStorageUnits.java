package com.adobexp.infralytiqs.scheduler.internal;

import java.math.BigDecimal;
/**
 * Canonical storage unit for Infralytiqs DAM disk-usage metrics: <b>decimal megabytes (MB)</b>.
 *
 * <p>All AEM REPORTS_API sizes and JCR-walk byte tallies are normalised to this unit before
 * ingest so pie charts and comparisons use one scale:
 * <ul>
 *   <li>{@code 1 GB} → {@code 1000} MB</li>
 *   <li>{@code 1 TB} → {@code 1_000_000} MB</li>
 *   <li>{@code 59.4 TB} → {@code 59_400_000} MB</li>
 * </ul>
 *
 * <p>Matches AEM Asset Reports decimal (SI) convention ({@code 1 MB = 10^6 B}).
 */
public final class AemStorageUnits {

    public static final String METRIC_MB_CUMULATIVE = "size_mb_cumulative";
    public static final String METRIC_MB_SELF = "size_mb_self";

    private static final BigDecimal MB_PER_BYTE = BigDecimal.ONE.movePointLeft(6);
    private static final BigDecimal MB_PER_KB = BigDecimal.ONE.movePointLeft(3);
    private static final BigDecimal MB_PER_MB = BigDecimal.ONE;
    private static final BigDecimal MB_PER_GB = BigDecimal.valueOf(1_000L);
    private static final BigDecimal MB_PER_TB = BigDecimal.valueOf(1_000_000L);
    private static final BigDecimal MB_PER_PB = BigDecimal.valueOf(1_000_000_000L);

    private AemStorageUnits() {
    }

    /** JCR rendition / folder byte tallies → decimal MB. */
    public static double bytesToDecimalMegabytes(long bytes) {
        if (bytes <= 0) {
            return 0d;
        }
        return BigDecimal.valueOf(bytes).multiply(MB_PER_BYTE).doubleValue();
    }

    /**
     * Parsed SIZE column → decimal MB ({@code "1 GB"} → {@code 1000}, {@code "1 TB"} →
     * {@code 1_000_000}).
     */
    public static double parseSizeToDecimalMegabytes(String raw) {
        AemReportsSizeParser.ParseResult parsed = AemReportsSizeParser.parse(raw);
        if (!parsed.parsed) {
            return 0d;
        }
        return toDecimalMegabytes(parsed.value, parsed.unit);
    }

    static double toDecimalMegabytes(BigDecimal value, String unitRaw) {
        if (value == null) {
            return 0d;
        }
        if (unitRaw == null || unitRaw.isEmpty()) {
            // Bare number in AEM CSV is bytes.
            return value.multiply(MB_PER_BYTE).doubleValue();
        }
        String unit = unitRaw.toUpperCase(java.util.Locale.ROOT);
        BigDecimal mult;
        switch (unit) {
            case "B":
                mult = MB_PER_BYTE;
                break;
            case "KB":
                mult = MB_PER_KB;
                break;
            case "MB":
                mult = MB_PER_MB;
                break;
            case "GB":
                mult = MB_PER_GB;
                break;
            case "TB":
                mult = MB_PER_TB;
                break;
            case "PB":
                mult = MB_PER_PB;
                break;
            default:
                mult = MB_PER_BYTE;
                break;
        }
        return value.multiply(mult).doubleValue();
    }
}
