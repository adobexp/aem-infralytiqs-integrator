package com.adobexp.infralytiqs.filters;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DownloadEventDeduperTest {

    private static final String PATH =
            "/content/dam/sample-tenant/sample-brand/general-use/work-best-work/image-and-print/Nivea A3 x3.pdf";

    @Test
    void suppressesSecondEventForSameUserAndPathWithinWindow() {
        DownloadEventDeduper deduper = new DownloadEventDeduper();
        assertFalse(deduper.isDuplicate("sharad", PATH));
        assertTrue(deduper.isDuplicate("sharad", PATH));
    }

    @Test
    void doesNotSuppressDifferentPathsForSameUser() {
        DownloadEventDeduper deduper = new DownloadEventDeduper();
        String otherPath =
                "/content/dam/sample-tenant/shared/general-use/case-studies/document/Case Study_Nivea_Implementation.pptx";

        assertFalse(deduper.isDuplicate("sharad", PATH));
        assertFalse(deduper.isDuplicate("sharad", otherPath));
    }

    @Test
    void doesNotSuppressSamePathForDifferentUsers() {
        DownloadEventDeduper deduper = new DownloadEventDeduper();
        assertFalse(deduper.isDuplicate("user-a", PATH));
        assertFalse(deduper.isDuplicate("user-b", PATH));
    }

    @Test
    void dedupKeyUsesAnonymousPlaceholderForBlankUser() {
        String key = DownloadEventDeduper.dedupKey("  ", PATH);
        assertTrue(key.startsWith("anonymous|"));
    }
}
