package com.adobexp.infralytiqs.filters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class DownloadPathNormalizerTest {

    @Test
    void normalize_decodesPercentEncodedSpaces() {
        String encoded =
                "/content/dam/sample-tenant/sample-brand/general-use/work-best-work/image-and-print/Nivea%20A3%20x3.pdf";
        String decoded =
                "/content/dam/sample-tenant/sample-brand/general-use/work-best-work/image-and-print/Nivea A3 x3.pdf";
        assertEquals(decoded, DownloadPathNormalizer.normalize(encoded));
    }

    @Test
    void normalize_leavesAlreadyDecodedPathUnchanged() {
        String decoded =
                "/content/dam/sample-tenant/shared/general-use/case-studies/document/Case Study_Nivea_Implementation.pptx";
        assertEquals(decoded, DownloadPathNormalizer.normalize(decoded));
    }

    @Test
    void normalize_handlesNullAndEmpty() {
        assertEquals("", DownloadPathNormalizer.normalize(null));
        assertEquals("", DownloadPathNormalizer.normalize(""));
    }

    @Test
    void encodedAndDecodedPathsCollapseToSameValue() {
        String encoded =
                "/content/dam/sample-tenant/shared/general-use/case-studies/document/Case%20Study_Nivea_Implementation.pptx";
        String decoded =
                "/content/dam/sample-tenant/shared/general-use/case-studies/document/Case Study_Nivea_Implementation.pptx";
        assertEquals(DownloadPathNormalizer.normalize(encoded), DownloadPathNormalizer.normalize(decoded));
    }
}
