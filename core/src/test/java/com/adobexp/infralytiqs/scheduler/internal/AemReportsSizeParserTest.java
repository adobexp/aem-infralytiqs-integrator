package com.adobexp.infralytiqs.scheduler.internal;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AemReportsSizeParserTest {

    @Test
    void parsesCellValueAndUnit() {
        AemReportsSizeParser.ParseResult r = AemReportsSizeParser.parse("8.4 TB");
        assertEquals(true, r.parsed);
        assertEquals("TB", r.unit);
    }

    @Test
    void parsesThousandsSeparator() {
        assertEquals(1234.5, AemStorageUnits.parseSizeToDecimalMegabytes("1,234.5 MB"), 0.001);
    }
}

