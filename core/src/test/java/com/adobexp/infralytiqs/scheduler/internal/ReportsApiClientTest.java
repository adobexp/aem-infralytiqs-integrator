package com.adobexp.infralytiqs.scheduler.internal;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportsApiClientTest {

    @Test
    void multipartBodyContainsLiteralTenantPath() {
        String tenant = "/content/dam/garnier";
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("path", ReportsApiClient.normalizeTenantPath(tenant));
        fields.put("jobTitle", "garnier-Infralytiqs-DiskUsage-20260519-120000");

        byte[] body = ReportsApiClient.buildMultipartFormBody(fields, "testBoundary");
        String text = new String(body, StandardCharsets.UTF_8);

        assertTrue(text.contains("name=\"path\""));
        assertTrue(text.contains(tenant), () -> "body should contain literal path, was: " + text);
        assertTrue(!text.contains("%2Fcontent%2Fdam"), "path slashes must not be percent-encoded");
    }

    @Test
    void normalizeTenantPathTrimsWhitespace() {
        assertEquals("/content/dam/visa", ReportsApiClient.normalizeTenantPath("  /content/dam/visa  "));
    }

    @Test
    void pathFieldForCreateJobUsesTenantRoot() {
        assertEquals("/content/dam/ask-the-lion",
                ReportsApiClient.pathFieldForCreateJob("/content/dam/ask-the-lion", "job-1"));
    }
}
