package com.adobexp.infralytiqs.scheduler.internal;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses AEM Asset Reports {@code SIZE} column values.
 *
 * <p>Downstream ingest uses {@link AemStorageUnits#parseSizeToDecimalMegabytes(String)} so every
 * folder is stored in decimal MB ({@code 1 GB → 1000 MB}, {@code 1 TB → 1_000_000 MB}).
 */
public final class AemReportsSizeParser {

    /**
     * Examples: {@code 57.6 MB}, {@code 1.2 GB}, {@code 8.4 TB}, {@code 512}, {@code 1,234.5 MB}.
     */
    private static final Pattern SIZE_RE = Pattern.compile(
            "^\\s*([0-9][0-9,]*(?:\\.[0-9]+)?)\\s*([KMGTP]?B)?\\s*$",
            Pattern.CASE_INSENSITIVE);

    private AemReportsSizeParser() {
    }

    /** @deprecated Prefer {@link AemStorageUnits#parseSizeToDecimalMegabytes(String)} for ingest. */
    @Deprecated
    public static long parseToBytes(String raw) {
        ParseResult r = parse(raw);
        if (!r.parsed) {
            return 0L;
        }
        if (r.unit == null || r.unit.isEmpty()) {
            return r.value.setScale(0, RoundingMode.HALF_UP).longValue();
        }
        BigDecimal bytes = r.value.multiply(byteMultiplier(r.unit));
        if (bytes.compareTo(BigDecimal.valueOf(Long.MAX_VALUE)) > 0) {
            return Long.MAX_VALUE;
        }
        return bytes.setScale(0, RoundingMode.HALF_UP).longValue();
    }

    public static final class ParseResult {
        public final BigDecimal value;
        public final String unit;
        public final boolean parsed;
        public final String raw;

        ParseResult(BigDecimal value, String unit, boolean parsed, String raw) {
            this.value = value;
            this.unit = unit;
            this.parsed = parsed;
            this.raw = raw;
        }
    }

    public static ParseResult parse(String raw) {
        if (raw == null) {
            return new ParseResult(BigDecimal.ZERO, null, false, null);
        }
        String cleaned = raw.replace("\"", "")
                .replace('\u00A0', ' ')
                .replace('\u202F', ' ')
                .trim();
        if (cleaned.isEmpty()) {
            return new ParseResult(BigDecimal.ZERO, null, false, raw);
        }
        Matcher m = SIZE_RE.matcher(cleaned);
        if (!m.matches()) {
            return new ParseResult(BigDecimal.ZERO, null, false, raw);
        }
        String num = m.group(1).replace(",", "");
        String unit = m.group(2);
        try {
            BigDecimal value = new BigDecimal(num);
            if (unit == null || unit.isEmpty()) {
                return new ParseResult(value, null, true, raw);
            }
            return new ParseResult(value, unit.toUpperCase(Locale.ROOT), true, raw);
        } catch (NumberFormatException ex) {
            return new ParseResult(BigDecimal.ZERO, null, false, raw);
        }
    }

    private static BigDecimal byteMultiplier(String unitRaw) {
        String unit = unitRaw.toUpperCase(Locale.ROOT);
        switch (unit) {
            case "B":
                return BigDecimal.ONE;
            case "KB":
                return BigDecimal.valueOf(1_000L);
            case "MB":
                return BigDecimal.valueOf(1_000_000L);
            case "GB":
                return BigDecimal.valueOf(1_000_000_000L);
            case "TB":
                return BigDecimal.valueOf(1_000_000_000_000L);
            case "PB":
                return BigDecimal.valueOf(1_000_000_000_000_000L);
            default:
                return BigDecimal.ONE;
        }
    }
}
