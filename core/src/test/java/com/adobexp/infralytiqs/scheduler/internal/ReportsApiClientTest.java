package com.adobexp.infralytiqs.scheduler.internal;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportsApiClientTest {

    @Test
    void generateJobTitleUsesLeafFolderName() {
        String title = ReportsApiClient.generateJobTitle("/content/dam/garnier");
        assertTrue(title.startsWith("garnier-DiskUsage-"), title);
    }

    @Test
    void generateJobTitleUsesLastSegmentForNestedPath() {
        String title = ReportsApiClient.generateJobTitle("/content/dam/px/arc");
        assertTrue(title.startsWith("arc-DiskUsage-"), title);
    }

    @Test
    void folderNameFromTenantPath() {
        assertEquals("visa", ReportsApiClient.folderNameFromTenantPath("/content/dam/visa"));
        assertEquals("dam", ReportsApiClient.folderNameFromTenantPath("/content/dam"));
    }
}
